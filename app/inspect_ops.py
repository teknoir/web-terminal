"""Read-only inspect executor (second listener, port 8091, wireguard mode only).

The Backstage backend asks this pod for four fixed, read-only operations on the
robot's device: ``pod``, ``events``, ``logs`` and ``release`` (the installed helm
release). The pod runs ``sudo -n k3s kubectl`` on the device over the same
``wg-connect`` ssh path the web terminal uses, with one ssh ControlMaster per user.

Rules, in short (the full wire contract is plans/nextgen/inspect.md section 3):

* No free text, no shell: every request field is validated against a strict
  pattern and the remote command is built from validated values only.
* The peer must be the Backstage backend (Istio ``X-Forwarded-Client-Cert`` URI
  in ``INSPECT_PRINCIPALS``); the AuthorizationPolicy is the real gate.
* The user is the email the backend vouches for (``X-Inspect-User``); the hub
  applies its organisation-unit and pods/exec gate to the ssh session as for a
  terminal.
* Output is capped and pruned; a helm release manifest is re-serialized from a strict parse
  (Secret values hidden) before anything is returned. Content is never logged.

The module is deliberately not called ``inspect.py``: app/ is on sys.path first
and would shadow the standard library module of that name.
"""
import asyncio
import base64
import binascii
import collections
import concurrent.futures
import hashlib
import heapq
import io
import json
import logging
import os
import re
import shlex
import secrets
import shutil
import signal
import threading
import time
import zlib

import tornado.ioloop
import tornado.web
import yaml

import wg_mode

logger = logging.getLogger(__name__)

WIRE_VERSION = 1
INSPECT_PATH = '/inspect/v1/op'
HEALTH_PATH = '/inspect/v1/healthz'
MAX_BODY = 4096
# Tornado's connection-level limit sits above MAX_BODY so that a too big body reaches the handler
# and is answered with the contract's JSON `invalid` (not a bare 400 without a body).
LISTEN_MAX_BODY = 64 * 1024
XFCC_HEADER = 'X-Forwarded-Client-Cert'
USER_HEADER = 'X-Inspect-User'
REQUEST_ID_HEADER = 'X-Request-Id'

# Limits (spec 3.6).
OP_TIMEOUT = 20.0
MASTER_TIMEOUT = 12.0
CHECK_TIMEOUT = 5.0
SLOT_WAIT = 5.0
MAX_CONCURRENT = 4
MAX_PER_USER = 2
MAX_OPS_PER_MIN = 120
MAX_MASTERS = 6
CONTROL_PERSIST = 60
SWEEP_INTERVAL = 60
KUBECTL_TIMEOUT = '15s'
STDERR_CAP = 16 * 1024
LOG_LIMIT_BYTES = 1024 * 1024
LOG_READ_CAP = LOG_LIMIT_BYTES + 64 * 1024
POD_CAP = 1024 * 1024
EVENTS_CAP = 2 * 1024 * 1024
RELEASE_LIST_CAP = 64 * 1024
RELEASE_SECRET_CAP = 3 * 1024 * 1024
# Spec 3.4/3.6 said 32 MiB; json.loads of a 32 MiB document of small objects would need several
# hundred MiB and the container has 256Mi, so the decoded release is capped at 8 MiB.
RELEASE_JSON_CAP = 8 * 1024 * 1024
# The backend refuses a manifest over 2 MiB (RELEASE_MAX_MANIFEST_BYTES), so the pod stops there too.
MANIFEST_CAP = 2 * 1024 * 1024
RELEASE_JSON_CONTAINERS = 400000      # objects plus arrays in the decoded release JSON
# Every manifest document is built into an object (to be written again), up to this size; a bigger
# one is replaced by a placeholder. Measured: a 1 MiB document of tiny items takes up to 160 MiB
# and 3 s, and the container has 256Mi for two jobs at once, so the cap is 256 KiB (at most ~40 MiB).
DOC_CAP = 256 * 1024
# Wall-time budget of one manifest redaction (the thread stops itself at the budget).
REDACT_BUDGET = 8.0
# Release shaping jobs that may exist at once (one running plus one waiting).
MAX_RELEASE_JOBS = 2
# Pod and events shaping jobs (fast, on their own worker thread so a release never delays them).
MAX_LIGHT_JOBS = 4
# json.loads builds ~65 bytes per object or array, and the caps allow a body of nothing but `{}`;
# the number of `{` and `[` in the raw bytes (an upper bound) is checked before parsing.
POD_JSON_CONTAINERS = 100000
EVENTS_JSON_CONTAINERS = 200000
# Wall-time budget of one pod or events shaping job.
LIGHT_BUDGET = 5.0
EVENTS_KEEP = 200
EVENT_MESSAGE_CAP = 1024
HISTORY_KEEP = 20
HIDDEN = '<hidden>'

# Field rules: the same patterns exist in the backend (TypeScript).
NAMESPACE_RE = re.compile(r'^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$')
POD_RE = wg_mode._K8S_NAME_RE
CONTAINER_RE = NAMESPACE_RE
RELEASE_RE = re.compile(r'^[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?$')
SINCE_RE = re.compile(r'^[1-9][0-9]{0,5}[smh]$')
REQUEST_ID_RE = re.compile(r'^[\w.-]{1,64}$')
PRINCIPAL_RE = re.compile(
    r'^cluster\.local/ns/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/sa/[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$')
MAX_SINCE_SECONDS = 168 * 3600
_SINCE_UNIT = {'s': 1, 'm': 60, 'h': 3600}

# Python flavour of the shared SECRET_KEY (TypeScript has `(?<!by|com)`).
SECRET_KEY = re.compile(
    r'((?<!by)(?<!com)pass(?!through)|pwd|secret|token|api[-_]?key|private|credential|dsn|auth(?!ors?(?![a-z])))',
    re.I)

# op -> {field: (kind, required)}
OPS = {
    'pod': {'namespace': ('namespace', True), 'pod': ('pod', True)},
    'events': {'namespace': ('namespace', True), 'pod': ('pod', True)},
    'logs': {'namespace': ('namespace', True), 'pod': ('pod', True), 'container': ('container', False),
             'previous': ('previous', False), 'tail': ('tail', False), 'since': ('since', False)},
    'release': {'namespace': ('namespace', True), 'release': ('release', True),
                'revision': ('revision', False)},
}
DEFAULT_TAIL = 500
MAX_TAIL = 2000

STATUS = {
    'invalid': 400, 'no_user': 401, 'forbidden': 403, 'not_found': 404, 'no_previous': 404,
    'not_started': 409, 'too_large': 413, 'busy': 429, 'session_limit': 429, 'device_error': 502,
    'offline': 503, 'unavailable': 503, 'timeout': 504, 'internal': 500,
}


class Failure(Exception):
    """An answer with an error code of the wire contract."""

    def __init__(self, code, message, retry_after=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after


# ---------------------------------------------------------------- validation

class Request:
    def __init__(self, op, fields):
        self.op = op
        self.fields = fields

    @property
    def namespace(self):
        return self.fields['namespace']

    @property
    def target(self):
        f = self.fields
        if self.op == 'release':
            rev = f.get('revision')
            return '%s/%s%s' % (f['namespace'], f['release'], '@%d' % rev if rev is not None else '')
        container = f.get('container')
        return '%s/%s%s' % (f['namespace'], f['pod'], '/' + container if container else '')


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_field(name, kind, value):
    if kind in ('namespace', 'pod', 'container', 'release'):
        pattern = {'namespace': NAMESPACE_RE, 'pod': POD_RE, 'container': CONTAINER_RE,
                   'release': RELEASE_RE}[kind]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise Failure('invalid', 'Field %s is not valid.' % name)
    elif kind == 'previous':
        if not isinstance(value, bool):
            raise Failure('invalid', 'Field previous must be true or false.')
    elif kind == 'tail':
        if not _is_int(value) or not 1 <= value <= MAX_TAIL:
            raise Failure('invalid', 'Field tail must be an integer from 1 to %d.' % MAX_TAIL)
    elif kind == 'revision':
        if not _is_int(value) or not 1 <= value <= 999999:
            raise Failure('invalid', 'Field revision must be an integer from 1 to 999999.')
    elif kind == 'since':
        if (not isinstance(value, str) or not SINCE_RE.fullmatch(value)
                or int(value[:-1]) * _SINCE_UNIT[value[-1]] > MAX_SINCE_SECONDS):
            raise Failure('invalid', 'Field since must look like 30m, 1h or 90s and be at most 168h.')


def parse_request(body):
    """Validate a decoded JSON body; returns a Request or raises Failure('invalid')."""
    if not isinstance(body, dict):
        raise Failure('invalid', 'The body must be a JSON object.')
    if not _is_int(body.get('v')) or body['v'] != WIRE_VERSION:
        raise Failure('invalid', 'Field v must be %d.' % WIRE_VERSION)
    op = body.get('op')
    if not isinstance(op, str) or op not in OPS:
        raise Failure('invalid', 'Unknown op.')
    spec = OPS[op]
    for key in body:
        if key not in spec and key not in ('v', 'op'):
            raise Failure('invalid', 'Unknown field %s.' % _printable(key, 40))
    fields = {}
    for name, (kind, required) in spec.items():
        if name not in body:
            if required:
                raise Failure('invalid', 'Field %s is required.' % name)
            continue
        _check_field(name, kind, body[name])
        fields[name] = body[name]
    return Request(op, fields)


def _printable(text, limit):
    return re.sub(r'[^\x20-\x7e]', '?', str(text))[:limit]


# ------------------------------------------------------------ remote commands

KUBECTL = ['sudo', '-n', 'k3s', 'kubectl', '--request-timeout=' + KUBECTL_TIMEOUT]
_LIST_JSONPATH = (r'jsonpath={range .items[*]}{.metadata.labels.version}{"\t"}'
                  r'{.metadata.labels.status}{"\n"}{end}')


def kubectl_argv(req, revision=None):
    """argv of the device command (after validation). `revision` for the release read."""
    f = req.fields
    if req.op == 'pod':
        return KUBECTL + ['-n', f['namespace'], 'get', 'pod', f['pod'], '-o', 'json']
    if req.op == 'events':
        return KUBECTL + ['-n', f['namespace'], 'get', 'events', '--field-selector',
                          'involvedObject.kind=Pod,involvedObject.name=' + f['pod'], '-o', 'json']
    if req.op == 'logs':
        argv = KUBECTL + ['-n', f['namespace'], 'logs', f['pod']]
        if f.get('container'):
            argv += ['-c', f['container']]
        if f.get('previous'):
            argv.append('--previous')
        argv.append('--tail=%d' % f.get('tail', DEFAULT_TAIL))
        if f.get('since'):
            argv.append('--since=' + f['since'])
        return argv + ['--timestamps', '--limit-bytes=%d' % LOG_LIMIT_BYTES]
    if req.op == 'release':
        if revision is None:
            return KUBECTL + ['-n', f['namespace'], 'get', 'secrets', '-l',
                              'owner=helm,name=' + f['release'], '-o', _LIST_JSONPATH]
        return KUBECTL + ['-n', f['namespace'], 'get', 'secret',
                          'sh.helm.release.v1.%s.v%d' % (f['release'], revision),
                          '-o', 'jsonpath={.data.release}']
    raise ValueError(req.op)


def remote_command(argv):
    return ' '.join(shlex.quote(a) for a in argv)


# ------------------------------------------------------------- stderr mapping

_DENIED_RE = re.compile(r'access denied: ([a-z_]+)(?: \((.*?)\))?\s*$', re.M)
_OFFLINE = ('device_offline', 'device_disabled', 'device_revoked', 'device_unknown', 'posture',
            'port_not_allowed')
_SENTENCE = {
    'device_offline': 'The robot is offline.',
    'device_disabled': 'The robot is disabled.',
    'device_revoked': 'The robot has been revoked.',
    'device_unknown': 'The robot is not known to the tunnel hub.',
    'posture': 'The robot does not meet the access posture.',
    'port_not_allowed': 'The tunnel hub does not allow this port.',
}


def _first_line(text, limit=300):
    for line in text.splitlines():
        line = re.sub(r'[^\x20-\x7e -￿]', ' ', line).strip()
        if line:
            return line[:limit]
    return ''


def classify_failure(stderr, rc, connection=False):
    """Map ssh/kubectl stderr to a Failure. `connection`: the command was ssh itself
    (master start), so every nonzero exit is a connection problem."""
    text = stderr.decode('utf-8', 'replace') if isinstance(stderr, bytes) else stderr
    connection_level = connection or rc == 255
    if connection_level:
        denied = _DENIED_RE.search(text)
        if denied:
            reason, detail = denied.group(1), denied.group(2)
            if reason == 'session_limit':
                return Failure('session_limit', 'You have the maximum number of sessions open to this robot.')
            if reason in ('forbidden', 'unauthenticated'):
                return Failure('forbidden', detail or 'Access to this robot is not allowed for you.')
            if reason in _OFFLINE:
                msg = _SENTENCE[reason] + (' (%s: %s)' % (reason, detail) if detail else ' (%s)' % reason)
                return Failure('offline', msg)
            if reason == 'rate_limited':
                return Failure('busy', 'The tunnel hub is rate limiting this robot. Try again in a moment.',
                               retry_after=5)
            return Failure('unavailable', 'The tunnel hub refused the session (%s).' % reason)
        if connection or rc == 255:
            line = _first_line(text)
            return Failure('unavailable', 'Could not open an ssh session to the robot.'
                           + (' ' + line if line else ''))
    if 'previous terminated container' in text:
        return Failure('no_previous', 'The container has no previous run to read.')
    if re.search(r'is waiting to start|ContainerCreating|PodInitializing', text):
        return Failure('not_started', 'The container has not started yet.')
    if 'sudo: a password is required' in text:
        return Failure('device_error', 'The device login user cannot run kubectl through sudo.')
    if re.search(r'\(NotFound\)|"[^"\n]*" not found', text, re.M):
        return Failure('not_found', 'Not found on the robot.')
    return Failure('device_error', _first_line(text) or 'kubectl failed (exit %s).' % rc)


# --------------------------------------------------------------- result shaping

def _pick(obj, keys):
    if not isinstance(obj, dict):
        return {}
    return {k: obj[k] for k in keys if k in obj}


def _as_list(value):
    return value if isinstance(value, list) else []


def _prune_container(c):
    out = _pick(c, ('name', 'image', 'imagePullPolicy', 'command', 'args', 'ports', 'resources', 'env',
                    'envFrom', 'volumeMounts'))
    if 'env' in out:
        env = []
        for e in _as_list(out['env']):
            if not isinstance(e, dict):
                continue
            e = dict(e)
            if isinstance(e.get('name'), str) and SECRET_KEY.search(e['name']) and 'value' in e:
                e['value'] = HIDDEN
            env.append(e)
        out['env'] = env
    if 'volumeMounts' in out:
        out['volumeMounts'] = [_pick(m, ('name', 'mountPath', 'readOnly')) for m in _as_list(out['volumeMounts'])]
    return out


def prune_pod(pod):
    if not isinstance(pod, dict):
        raise Failure('device_error', 'The device answered with something that is not a pod.')
    meta_in = pod.get('metadata') if isinstance(pod.get('metadata'), dict) else {}
    meta = _pick(meta_in, ('name', 'namespace', 'uid', 'creationTimestamp', 'labels'))
    refs = [_pick(r, ('kind', 'name')) for r in _as_list(meta_in.get('ownerReferences'))]
    if refs:
        meta['ownerReferences'] = refs
    spec_in = pod.get('spec') if isinstance(pod.get('spec'), dict) else {}
    spec = _pick(spec_in, ('nodeName', 'restartPolicy', 'serviceAccountName', 'priorityClassName'))
    for key in ('containers', 'initContainers'):
        if key in spec_in:
            spec[key] = [_prune_container(c) for c in _as_list(spec_in[key])]
    if 'volumes' in spec_in:
        vols = []
        for v in _as_list(spec_in['volumes']):
            if not isinstance(v, dict):
                continue
            kinds = [k for k in v if k != 'name']
            vols.append({'name': v.get('name'), 'type': kinds[0] if kinds else None})
        spec['volumes'] = vols
    status = _pick(pod.get('status'), ('phase', 'reason', 'message', 'qosClass', 'startTime', 'podIP', 'hostIP',
                                       'conditions', 'containerStatuses', 'initContainerStatuses'))
    return {'metadata': meta, 'spec': spec, 'status': status}


def shape_events(doc, deadline=None):
    """Newest EVENTS_KEEP events, oldest first. Only a bounded heap of finished rows is kept while
    iterating (a row is built only when it can still make the cut), so a huge item list never
    becomes a huge row list."""
    if not isinstance(doc, dict):
        raise Failure('device_error', 'The device answered with something that is not an event list.')
    heap = []                                  # (last, index, row): the smallest is the first to go
    total = 0
    for i, e in enumerate(_as_list(doc.get('items'))):
        if not i & 0x3FF:
            _check_budget(deadline)
        if not isinstance(e, dict):
            continue
        total += 1
        series = e.get('series') if isinstance(e.get('series'), dict) else {}
        last = e.get('lastTimestamp') or series.get('lastObservedTime') or e.get('eventTime')
        key = (str(last or ''), i)
        if len(heap) >= EVENTS_KEEP and key <= heap[0][:2]:
            continue
        source = e.get('source') if isinstance(e.get('source'), dict) else {}
        message = e.get('message')
        row = {
            'type': e.get('type'),
            'reason': e.get('reason'),
            'message': message[:EVENT_MESSAGE_CAP] if isinstance(message, str) else message,
            'count': e.get('count') or series.get('count'),
            'first': e.get('firstTimestamp') or e.get('eventTime'),
            'last': last,
            'source': source.get('component') or e.get('reportingController'),
        }
        if len(heap) >= EVENTS_KEEP:
            heapq.heappushpop(heap, (key[0], key[1], row))
        else:
            heapq.heappush(heap, (key[0], key[1], row))
    heap.sort(key=lambda t: t[:2])
    return {'events': [t[2] for t in heap], 'truncated': total > EVENTS_KEEP}


def shape_pod_json(raw, deadline=None):
    """Raw `kubectl get pod -o json` stdout -> the pruned pod. Runs on a worker thread."""
    doc = _json(raw, POD_JSON_CONTAINERS)
    _check_budget(deadline)
    out = prune_pod(doc)
    _check_budget(deadline)
    return out


def shape_events_json(raw, deadline=None):
    """Raw `kubectl get events -o json` stdout -> the events result. Runs on a worker thread."""
    doc = _json(raw, EVENTS_JSON_CONTAINERS)
    _check_budget(deadline)
    return shape_events(doc, deadline)


_DEFAULTED_RE = re.compile(r'Defaulted container "([^"]+)"')


def shape_logs(raw, stderr, req, over):
    """`raw`: stdout bytes (at most LOG_READ_CAP); `over`: the read cap was hit."""
    f = req.fields
    tail = f.get('tail', DEFAULT_TAIL)
    cut = over or len(raw) >= LOG_LIMIT_BYTES
    if len(raw) > LOG_LIMIT_BYTES:
        raw = raw[:LOG_LIMIT_BYTES]
    text = raw.decode('utf-8', 'backslashreplace')
    encoded = text.encode('utf-8')
    if len(encoded) > LOG_LIMIT_BYTES:    # invalid bytes grow when escaped; keep the contract
        text = encoded[:LOG_LIMIT_BYTES].decode('utf-8', 'ignore')
        cut = True
    if cut and '\n' in text:
        text = text[:text.rindex('\n') + 1]   # drop the line the cap cut in half
    lines = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
    container = f.get('container')
    if not container:
        m = _DEFAULTED_RE.search(stderr.decode('utf-8', 'replace'))
        container = m.group(1) if m else None
    return {'text': text, 'lines': lines, 'bytes': len(text.encode('utf-8')), 'container': container,
            'previous': bool(f.get('previous', False)),
            'truncated': {'bytes': cut, 'lines': lines == tail}}


# --------------------------------------------------------------- helm releases

def parse_release_list(raw):
    rows = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        version, _, status = line.partition('\t')
        if version.isascii() and version.isdigit() and 0 < int(version) < 1000000 and status:
            rows.append((int(version), status.strip()))
    rows.sort(reverse=True)
    return rows


def pick_revision(rows, wanted):
    if wanted is not None:
        return wanted if any(v == wanted for v, _ in rows) else None
    for version, status in rows:
        if status == 'deployed':
            return version
    return rows[0][0] if rows else None


def decode_release(secret_b64):
    """Secret `data.release` (k8s base64) -> the pruned release dict. Raises Failure."""
    try:
        inner = base64.b64decode(secret_b64.strip(), validate=True)      # k8s
        blob = base64.b64decode(inner, validate=True)                    # helm
    except (binascii.Error, ValueError):
        raise Failure('device_error', 'The release record on the robot could not be decoded.')
    if blob[:3] == b'\x1f\x8b\x08':
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            blob = d.decompress(blob, RELEASE_JSON_CAP + 1)
        except zlib.error:
            raise Failure('device_error', 'The release record on the robot could not be decoded.')
        if len(blob) > RELEASE_JSON_CAP or d.unconsumed_tail:
            raise Failure('too_large', 'The release record is too large to read.')
    # json.loads needs ~65 bytes per object or array: bound the count (an upper bound, braces inside
    # strings count too) before building them, or 8 MiB of `{}` would take ~250 MiB.
    if blob.count(b'{') + blob.count(b'[') > RELEASE_JSON_CONTAINERS:
        raise Failure('too_large', 'The release record is too complex to read.')
    try:
        rel = json.loads(blob)
    except (RecursionError, MemoryError):          # deeply nested or huge: not a record to read
        raise Failure('too_large', 'The release record is too complex to read.')
    except ValueError:
        raise Failure('device_error', 'The release record on the robot could not be decoded.')
    if not isinstance(rel, dict):
        raise Failure('device_error', 'The release record on the robot could not be decoded.')
    info = rel.get('info') if isinstance(rel.get('info'), dict) else {}
    chart = rel.get('chart') if isinstance(rel.get('chart'), dict) else {}
    meta = chart.get('metadata') if isinstance(chart.get('metadata'), dict) else {}
    manifest = rel.get('manifest')
    kept = {
        'name': rel.get('name'), 'namespace': rel.get('namespace'), 'version': rel.get('version'),
        'status': info.get('status'), 'last_deployed': info.get('last_deployed'),
        'chart': meta.get('name'), 'chartVersion': meta.get('version'), 'appVersion': meta.get('appVersion'),
        'manifest': manifest if isinstance(manifest, str) else '',
    }
    return kept


# libyaml's parser, never the pure-Python one: the scanner differences between the two (and
# go-yaml, which Kubernetes uses) are exactly what a redactor must not depend on. Without libyaml
# the inspect listener does not start (start_inspect_listener) and every document is hidden.
_YAML_LOADER = getattr(yaml, 'CSafeLoader', None)

_DOC_SPLIT = re.compile(r'^---[ \t]*$', re.M)
_LAST_APPLIED = 'last-applied-configuration'
# Kubernetes and go-yaml treat \r, U+0085, U+2028 and U+2029 as line breaks, skip a BOM at the start
# of any line, and ignore characters a YAML reader here may handle differently. A document that has
# any of them (or any other control character but tab and newline, or something that is not valid
# UTF-8, which in a decoded string is a lone surrogate) is hidden whole: helm never renders them.
_UNUSUAL = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f  ﻿￾￿\ud800-\udfff]')
COMMENTS_NOTE = '# comments are not shown'
MAX_YAML_DEPTH = 64     # nesting beyond this is never shown (the dump below recurses in Python)
_RESOLVER = yaml.resolver.Resolver()
_CONSTRUCTOR = yaml.constructor.SafeConstructor()
_STR_TAG = 'tag:yaml.org,2002:str'

# What the placeholder of a hidden document says.
_R_CHARS = 'unusual characters'
_R_BIG = 'document is too large to show'
_R_DEEP = 'document is too deep to show'
_R_TAGS = 'document uses YAML aliases, anchors, merge keys or tags'
_R_DIRECTIVE = 'document uses YAML directives'
_R_LIST = 'document is a list'
_R_ODD = 'document is not a plain Kubernetes object'
_R_PARSE = 'document could not be parsed'


class _Hidden(Exception):
    """The document must be replaced whole by a placeholder; `args[0]` is the reason."""


def _check_budget(deadline):
    if deadline is not None and time.monotonic() > deadline:
        raise Failure('too_large', 'This is too complex to read within the time limit.')


def _scalar(ev):
    """The Python value of a scalar event: quoted scalars are strings, plain ones are resolved like
    yaml.safe_load does (a tag never reaches here: tags hide the document)."""
    tag = _RESOLVER.resolve(yaml.ScalarNode, ev.value, ev.implicit)
    if tag == _STR_TAG:
        return ev.value
    return _CONSTRUCTOR.yaml_constructors[tag](_CONSTRUCTOR, yaml.ScalarNode(tag, ev.value))


def _is_plain_string(ev):
    return _RESOLVER.resolve(yaml.ScalarNode, ev.value, ev.implicit) == _STR_TAG


def _parse_document(body, deadline):
    """Build the one YAML document in `body` out of libyaml's events, with nothing composed and no
    recursion, and refuse (raise _Hidden) everything that two parsers could read differently or that
    could carry a value around a redaction. Returns the plain dict, or None for a text that holds no
    document at all (nothing but comments and blank lines).

    Refused: a second document, a directive or an explicit `---`, any alias, anchor or tag (the standard
    tags too), a merge key `<<` (quoted or not), a key given twice, a key that is not a plain string or
    is a collection, a list directly in a list, nesting deeper than MAX_YAML_DEPTH, a root that is not
    a mapping, a top-level key with a non-ASCII character (Go folds some of them to ASCII), a top-level
    `items` or `kind` key in any other letter case, a `kind` that is missing, not a plain string or ends
    in `list` (any letter case)."""
    stack = []             # open collections: [container, pending key or None]
    documents = 0
    root = None
    count = 0
    for ev in yaml.parse(body, Loader=_YAML_LOADER):
        count += 1
        if not count & 0x3FF:
            _check_budget(deadline)
        if isinstance(ev, yaml.DocumentStartEvent):
            documents += 1
            if documents > 1:
                raise _Hidden(_R_ODD)
            if ev.explicit or ev.version is not None or ev.tags:
                raise _Hidden(_R_DIRECTIVE)
            continue
        if isinstance(ev, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            stack.pop()
            continue
        if not isinstance(ev, (yaml.ScalarEvent, yaml.AliasEvent, yaml.MappingStartEvent,
                               yaml.SequenceStartEvent)):
            continue                                   # stream and document end markers
        if isinstance(ev, yaml.AliasEvent) or ev.anchor is not None or ev.tag is not None:
            raise _Hidden(_R_TAGS)
        scalar = isinstance(ev, yaml.ScalarEvent)
        mapping = isinstance(ev, yaml.MappingStartEvent)
        top = stack[-1] if stack else None
        as_key = top is not None and isinstance(top[0], dict) and top[1] is None
        if not stack and not mapping:
            raise _Hidden(_R_ODD)                      # the root is not a mapping
        if as_key:
            if scalar and ev.value == '<<':
                raise _Hidden(_R_TAGS)                 # a merge key, plain or quoted
            if not scalar or not _is_plain_string(ev):
                raise _Hidden(_R_ODD)                  # a complex key or one that is not a string
            key = ev.value
            if key in top[0]:
                raise _Hidden(_R_ODD)
            if len(stack) == 1:
                if not key.isascii():
                    raise _Hidden(_R_ODD)
                lowered = key.lower()
                if lowered == 'items':
                    raise _Hidden(_R_LIST)
                if lowered == 'kind' and key != 'kind':
                    raise _Hidden(_R_ODD)
            top[1] = key
            continue
        if scalar:
            value = _scalar(ev)
        else:
            if not mapping and top is not None and isinstance(top[0], list):
                raise _Hidden(_R_LIST)                 # a list directly in a list
            if len(stack) >= MAX_YAML_DEPTH:
                raise _Hidden(_R_DEEP)
            value = {} if mapping else []
        if top is None:
            root = value
        elif isinstance(top[0], list):
            top[0].append(value)
        else:
            if len(stack) == 1 and top[1] == 'kind' and not (scalar and _is_plain_string(ev)):
                raise _Hidden(_R_ODD)                  # the kind is a plain string
            top[0][top[1]] = value
            top[1] = None
        if not scalar:
            stack.append([value, None])
    if documents == 0:
        return None
    kind = root.get('kind')
    if not isinstance(kind, str):
        raise _Hidden(_R_ODD)
    if kind.strip().lower().endswith('list'):
        raise _Hidden(_R_LIST)
    return root


def _is_secret(obj):
    return obj['kind'].strip().lower() == 'secret'


def _secret_view(obj):
    """What may be shown of a Secret: apiVersion, kind, type and immutable as they are (when they are
    plain scalars), the metadata without managedFields and without last-applied-configuration
    annotations, and the keys of data, stringData and binaryData with their values hidden. Every
    other top-level field is dropped (Kubernetes ignores them in a Secret)."""
    out = {}
    for key in ('apiVersion', 'kind', 'metadata', 'type', 'immutable', 'data', 'stringData', 'binaryData'):
        if key not in obj:
            continue
        value = obj[key]
        if key in ('data', 'stringData', 'binaryData'):
            out[key] = {k: HIDDEN for k in value} if isinstance(value, dict) else HIDDEN
        elif key == 'metadata':
            if isinstance(value, dict):
                out[key] = _metadata_view(value)
        elif not isinstance(value, (dict, list)):
            out[key] = value
    return out


def _metadata_view(meta):
    out = {}
    for key, value in meta.items():
        lowered = key.lower() if key.isascii() else None
        if lowered is None or lowered == 'managedfields':
            continue                                   # non-ASCII keys could fold to either name
        if lowered == 'annotations':
            if not isinstance(value, dict):
                continue
            kept = {k: v for k, v in value.items() if k.isascii() and _LAST_APPLIED not in k.lower()}
            if not kept and value:
                continue                               # only last-applied-configuration was there
            value = kept
        out[key] = value
    return out


def _iter_documents(manifest):
    """The text between `---` separator lines, one at a time (no list of them is built). Only a
    line of exactly `---` plus blanks separates; a chunk is contiguous text, so every character of
    the manifest outside the separators is checked by the per-document character gate."""
    pos = 0
    for m in _DOC_SPLIT.finditer(manifest):
        yield manifest[pos:m.start()]
        pos = m.end()
    yield manifest[pos:]


def _render_document(chunk, deadline):
    """One manifest chunk -> the text to show, or None when it holds no document. The output is
    always a re-serialization of the parsed object, never the original text."""
    if _YAML_LOADER is None:
        return '# <hidden: %s>' % _R_PARSE
    try:
        if _UNUSUAL.search(chunk):
            raise _Hidden(_R_CHARS)
        if len(chunk) > DOC_CAP or len(chunk.encode('utf-8')) > DOC_CAP:
            raise _Hidden(_R_BIG)
        obj = _parse_document(chunk, deadline)
        if obj is None:
            return None
        if _is_secret(obj):
            obj = _secret_view(obj)
        # allow_unicode stays off: anything that came in through an escape ( , \x85 ...) goes
        # out as an escape again, so the text shown never holds a character the gate refuses.
        return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False).rstrip('\n')
    except Failure:
        raise
    except _Hidden as hidden:
        return '# <hidden: %s>' % hidden.args[0]
    except Exception:
        return '# <hidden: %s>' % _R_PARSE


def redact_manifest(manifest, deadline=None):
    """The manifest as shown to people: every document re-serialized from the parsed object
    (comments are dropped), Secrets reduced to their keys, whatever is odd hidden whole."""
    out = io.StringIO()
    written = 0
    for chunk in _iter_documents(manifest):
        _check_budget(deadline)
        if not chunk.strip():
            continue
        shown = _render_document(chunk, deadline)
        if shown is None:
            continue
        if not written:
            out.write(COMMENTS_NOTE + '\n')
        doc = '---\n%s\n' % shown
        written += len(doc)
        if written > MANIFEST_CAP:                     # characters never outnumber bytes
            raise Failure('too_large', 'The rendered manifest is too large to read.')
        out.write(doc)
    text = out.getvalue()
    if len(text.encode('utf-8')) > MANIFEST_CAP:
        raise Failure('too_large', 'The rendered manifest is too large to read.')
    return text


def shape_release(secret_b64, rows, name, namespace, revision, budget=REDACT_BUDGET):
    """Decode, check it is the release asked for, drop everything but the allowed fields,
    redact. Runs in a thread; `budget` is the wall time it may take."""
    deadline = time.monotonic() + budget
    kept = decode_release(secret_b64)
    if (kept['name'], kept['namespace']) != (name, namespace) or not _is_int(kept['version']) \
            or kept['version'] != revision:
        raise Failure('device_error', 'The release record on the robot does not match the request.')
    if len(kept['manifest'].encode('utf-8')) > MANIFEST_CAP:     # before any splitting or parsing
        raise Failure('too_large', 'The rendered manifest is too large to read.')
    manifest = redact_manifest(kept['manifest'], deadline)
    history = [{'revision': v, 'status': s} for v, s in rows[:HISTORY_KEEP]]
    result = {
        'name': name, 'namespace': namespace, 'revision': revision,
        'status': kept['status'], 'chart': kept['chart'], 'chartVersion': kept['chartVersion'],
        'manifest': manifest, 'history': history,
    }
    if kept['appVersion']:
        result['appVersion'] = kept['appVersion']
    if kept['last_deployed']:
        result['lastDeployed'] = kept['last_deployed']
    return result


# ------------------------------------------------------------------- the runner

def _killpg(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def _read_capped(stream, cap, on_over=None):
    """Read to EOF keeping at most `cap` bytes. Returns (bytes, over). With `on_over`
    the read stops at the cap and the callback runs (to kill the process)."""
    buf = bytearray()
    over = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if len(buf) + len(chunk) > cap:
            over = True
            buf += chunk[:cap - len(buf)]
            if on_over is not None:
                on_over()
                break
            continue   # drain (stderr)
        buf += chunk
    return bytes(buf), over


class UserState:
    def __init__(self, email, directory):
        self.email = email
        self.dir = directory
        self.lock = asyncio.Lock()
        self.sem = asyncio.Semaphore(MAX_PER_USER)
        self.active = 0
        self.stamps = collections.deque()

    @property
    def control_path(self):
        return os.path.join(self.dir, 'cm')

    @property
    def known_hosts(self):
        return os.path.join(self.dir, 'known_hosts')


class InspectRunner:
    def __init__(self, config, ssh='ssh', base_dir=None, op_timeout=OP_TIMEOUT, master_timeout=MASTER_TIMEOUT,
                 slot_wait=SLOT_WAIT, max_concurrent=MAX_CONCURRENT, max_masters=MAX_MASTERS,
                 rate_per_min=MAX_OPS_PER_MIN, clock=time.monotonic, redact_budget=REDACT_BUDGET):
        self.config = config
        self.ssh = ssh
        self.base_dir = base_dir or os.path.join(os.environ.get('TMPDIR') or '/tmp', 'inspect')
        self.op_timeout = op_timeout
        self.master_timeout = master_timeout
        self.slot_wait = slot_wait
        self.max_masters = max_masters
        self.rate_per_min = rate_per_min
        self.clock = clock
        self.redact_budget = redact_budget
        self._jobs = 0                       # release jobs queued or running
        self._light_jobs = 0                 # pod and events jobs queued or running
        self._jobs_lock = threading.Lock()
        self.global_sem = asyncio.Semaphore(max_concurrent)
        self.states = collections.OrderedDict()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='inspect')
        self.light_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='inspect-light')

    # -- per-user state

    def _user_dir(self, email):
        """The live state's directory; a fresh unique one when the user has no state.
        Every state gets its own directory (hash plus random suffix), so a late cleanup of an
        evicted state can never touch the directory of its successor."""
        st = self.states.get(email)
        if st is not None:
            return st.dir
        return os.path.join(self.base_dir, 'u-%s-%s' % (hashlib.sha256(email.encode()).hexdigest()[:16],
                                                       secrets.token_hex(4)))

    async def _acquire_state(self, email):
        """The user's state with `active` already incremented (so it is not evicted)."""
        st = self.states.get(email)
        if st is not None:
            self.states.move_to_end(email)
            st.active += 1
            return st
        while len(self.states) >= self.max_masters:
            victim = next((s for s in self.states.values() if s.active == 0 and not s.lock.locked()), None)
            if victim is None:
                raise Failure('busy', 'Too many robot sessions are in use. Try again in a moment.',
                              retry_after=5)
            del self.states[victim.email]
            await self._close_state(victim)
        os.makedirs(self.base_dir, mode=0o700, exist_ok=True)
        os.chmod(self.base_dir, 0o700)
        directory = self._user_dir(email)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        st = self.states.get(email)     # another request may have created it meanwhile
        if st is None:
            st = self.states[email] = UserState(email, directory)
        st.active += 1
        return st

    async def _close_state(self, st):
        try:
            await self._ssh_control(st, 'exit')
        except Exception:
            logger.debug('closing master failed', exc_info=True)
        shutil.rmtree(st.dir, ignore_errors=True)

    def _base_args(self, st):
        return [self.ssh] + self.config.ssh_options(st.email, st.known_hosts) + [
            '-T', '-o', 'BatchMode=yes', '-S', st.control_path]

    async def _ssh_control(self, st, what):
        rc, _, _, _ = await self._run(self._base_args(st) + ['-O', what, self.config.destination],
                                      max_out=4096, timeout=CHECK_TIMEOUT)
        return rc == 0

    def _check_rate(self, st):
        now = self.clock()
        while st.stamps and now - st.stamps[0] > 60:
            st.stamps.popleft()
        if len(st.stamps) >= self.rate_per_min:
            raise Failure('busy', 'Too many inspect requests. Try again in a moment.', retry_after=5)
        st.stamps.append(now)

    # -- processes

    async def _run(self, argv, max_out, timeout, stderr_path=None, discard_stdout=False):
        """Run argv in its own process group. Returns (rc, stdout, stderr, over)."""
        err_file = open(stderr_path, 'wb') if stderr_path else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL if discard_stdout else asyncio.subprocess.PIPE,
                stderr=err_file if err_file else asyncio.subprocess.PIPE,
                start_new_session=True)
        except OSError:
            raise Failure('internal', 'The ssh client could not be started in the inspect pod.')
        finally:
            if err_file:
                err_file.close()
        out, err, over = b'', b'', False
        try:
            async def work():
                nonlocal out, err, over
                if stderr_path:
                    rc = await proc.wait()
                    with open(stderr_path, 'rb') as fh:
                        err = fh.read(STDERR_CAP)
                    return rc
                (out, over), (err, _) = await asyncio.gather(
                    _read_capped(proc.stdout, max_out, on_over=lambda: _killpg(proc)),
                    _read_capped(proc.stderr, STDERR_CAP))
                return await proc.wait()
            rc = await asyncio.wait_for(work(), timeout)
        except BaseException:
            _killpg(proc)
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except Exception:
                pass
            raise
        return rc, out, err, over

    async def _ensure_master(self, st):
        async with st.lock:
            if await self._ssh_control(st, 'check'):
                return
            try:
                os.unlink(st.control_path)
            except FileNotFoundError:
                pass
            argv = self._base_args(st) + ['-o', 'ControlMaster=yes', '-o', 'ControlPersist=%d' % CONTROL_PERSIST,
                                          '-N', '-f', self.config.destination]
            err_path = os.path.join(st.dir, 'master.err')
            try:
                rc, _, err, _ = await self._run(argv, max_out=4096, timeout=self.master_timeout,
                                                stderr_path=err_path, discard_stdout=True)
            except asyncio.TimeoutError:
                raise Failure('timeout', 'The robot did not answer in time.')
            finally:
                try:
                    os.unlink(err_path)
                except OSError:
                    pass
            if rc != 0:
                raise classify_failure(err, rc, connection=True)

    async def _remote(self, st, argv, max_out):
        full = self._base_args(st) + ['-o', 'ControlMaster=no', self.config.destination, '--',
                                      remote_command(argv)]
        rc, out, err, over = await self._run(full, max_out=max_out, timeout=self.op_timeout)
        return rc, out, err, over

    async def _kubectl(self, st, argv, max_out, allow_over=False):
        rc, out, err, over = await self._remote(st, argv, max_out)
        if over and not allow_over:
            raise Failure('too_large', 'The answer from the robot is too large to read.')
        if rc != 0 and not (over and allow_over):
            raise classify_failure(err, rc)
        return out, err, over

    # -- ops

    async def execute(self, email, req):
        """Run one validated Request for `email`. Returns (result dict, stdout bytes)."""
        try:
            return await asyncio.wait_for(self._execute(email, req), self.op_timeout)
        except asyncio.TimeoutError:
            raise Failure('timeout', 'The robot did not answer within %d s.' % self.op_timeout)

    async def _execute(self, email, req):
        st = await self._acquire_state(email)
        try:
            self._check_rate(st)
            async with self._slots(st):
                await self._ensure_master(st)
                return await self._dispatch(st, req)
        finally:
            st.active -= 1

    def _slots(self, st):
        runner = self

        class Slots:
            async def __aenter__(self):
                try:
                    await asyncio.wait_for(st.sem.acquire(), runner.slot_wait)
                except asyncio.TimeoutError:
                    raise Failure('busy', 'You already have the maximum number of inspect requests running.',
                                  retry_after=5)
                try:
                    await asyncio.wait_for(runner.global_sem.acquire(), runner.slot_wait)
                except asyncio.TimeoutError:
                    st.sem.release()
                    raise Failure('busy', 'This robot is busy with other inspect requests. Try again.',
                                  retry_after=5)

            async def __aexit__(self, *exc):
                runner.global_sem.release()
                st.sem.release()
        return Slots()

    async def _dispatch(self, st, req):
        loop = asyncio.get_running_loop()
        if req.op == 'pod':
            out, _, _ = await self._kubectl(st, kubectl_argv(req), POD_CAP)
            pod = await self._light_job(shape_pod_json, out)
            return {'pod': pod}, len(out)
        if req.op == 'events':
            out, _, _ = await self._kubectl(st, kubectl_argv(req), EVENTS_CAP)
            return await self._light_job(shape_events_json, out), len(out)
        if req.op == 'logs':
            out, err, over = await self._kubectl(st, kubectl_argv(req), LOG_READ_CAP, allow_over=True)
            return shape_logs(out, err, req, over), len(out)
        # release
        listing, _, _ = await self._kubectl(st, kubectl_argv(req), RELEASE_LIST_CAP)
        rows = parse_release_list(listing)
        if not rows:
            raise Failure('not_found', 'No helm release %s in namespace %s on the robot.'
                          % (req.fields['release'], req.namespace))
        revision = pick_revision(rows, req.fields.get('revision'))
        if revision is None:
            raise Failure('not_found', 'Revision %d of release %s does not exist.'
                          % (req.fields['revision'], req.fields['release']))
        secret, _, _ = await self._kubectl(st, kubectl_argv(req, revision), RELEASE_SECRET_CAP)
        result = await self._shape_release(loop, secret.decode('ascii', 'replace'), rows,
                                           req.fields['release'], req.namespace, revision)
        return result, len(secret)

    async def _shape_release(self, loop, secret, rows, name, namespace, revision):
        """shape_release on the worker thread. The thread stops itself at its time budget, and the
        jobs are bounded: a job that outlives its op (timeout) still counts until it ends."""
        budget = self.redact_budget
        return await self._run_job(
            self.pool, '_jobs', MAX_RELEASE_JOBS,
            lambda: shape_release(secret, rows, name, namespace, revision, budget=budget))

    async def _light_job(self, fn, raw):
        """Parse and shape pod or events JSON on the light worker thread, with the same kind of
        deadline: nothing device-controlled is parsed on the event loop."""
        deadline = time.monotonic() + LIGHT_BUDGET
        return await self._run_job(self.light_pool, '_light_jobs', MAX_LIGHT_JOBS, lambda: fn(raw, deadline))

    async def _run_job(self, pool, counter, limit, fn):
        """Run `fn` on `pool` with an exact slot count in `self.<counter>`: the slot is taken before
        the job is submitted and given back by a done-callback of the submitted future, which fires
        exactly once when the job ends, raises, or is cancelled while still queued (a job that was
        cancelled in the queue never runs, so only the future knows). A running job that outlives
        its op (timeout) keeps its slot until it ends."""
        with self._jobs_lock:
            if getattr(self, counter) >= limit:
                raise Failure('busy', 'The inspect pod is still busy with other jobs. Try again.',
                              retry_after=5)
            setattr(self, counter, getattr(self, counter) + 1)

        def give_back(_future):
            with self._jobs_lock:
                setattr(self, counter, getattr(self, counter) - 1)
        try:
            future = pool.submit(fn)
        except BaseException:                    # executor shut down: nothing was queued
            give_back(None)
            raise
        future.add_done_callback(give_back)
        return await asyncio.wrap_future(future)

    # -- housekeeping

    async def sweep(self):
        """Forget users whose master is gone (idle for ControlPersist) and delete their dirs."""
        for email, st in list(self.states.items()):
            if st.active == 0 and not st.lock.locked() and not os.path.exists(st.control_path):
                self.states.pop(email, None)
                shutil.rmtree(st.dir, ignore_errors=True)
        try:
            names = os.listdir(self.base_dir)
        except OSError:
            return
        known = {os.path.basename(s.dir) for s in self.states.values()}
        for name in names:
            path = os.path.join(self.base_dir, name)
            if name.startswith('u-') and name not in known and not os.path.exists(os.path.join(path, 'cm')):
                shutil.rmtree(path, ignore_errors=True)

    async def close(self):
        states = list(self.states.values())
        self.states.clear()
        for st in states:
            await self._close_state(st)
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.light_pool.shutdown(wait=False, cancel_futures=True)


def _json(raw, max_containers=None):
    """json.loads of device output. `max_containers` bounds the objects plus arrays (counted on the
    raw bytes, an upper bound) before anything is built."""
    if max_containers is not None and raw.count(b'{') + raw.count(b'[') > max_containers:
        raise Failure('too_large', 'The device answered with something too complex to read.')
    try:
        return json.loads(raw)
    except (RecursionError, MemoryError):
        raise Failure('too_large', 'The device answered with something too large or too nested to read.')
    except ValueError:
        raise Failure('device_error', 'The device answered with something that is not JSON.')


# --------------------------------------------------------------------- HTTP

def _split_quoted(text, sep):
    """Split on `sep` outside double quotes. Returns (parts, balanced); `balanced` is False
    when a quote is left open or ends in a dangling escape."""
    parts, cur, quoted, escaped = [], [], False, False
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == '\\' and quoted:
            cur.append(ch)
            escaped = True
        elif ch == '"':
            quoted = not quoted
            cur.append(ch)
        elif ch == sep and not quoted:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append(''.join(cur))
    return parts, not quoted and not escaped


def xfcc_uris(values):
    """URI entries of the X-Forwarded-Client-Cert header, or [] (fail closed) unless the
    joined header is exactly one element with balanced quotes. Istio appends Envoy's element
    to whatever the caller sent, and the backend never sends one, so a real request carries
    only Envoy's element; anything else is forged or malformed."""
    elements, balanced = _split_quoted(','.join(values), ',')
    if not balanced:
        return []
    elements = [e for e in elements if e.strip()]
    if len(elements) != 1:
        return []
    pairs, balanced = _split_quoted(elements[0], ';')
    if not balanced:
        return []
    uris = []
    for pair in pairs:
        key, _, value = pair.strip().partition('=')
        if key.lower() == 'uri':
            uris.append(value.strip().strip('"'))
    return uris


def parse_principals(raw):
    """INSPECT_PRINCIPALS (comma list) -> the valid entries; invalid ones are logged and dropped."""
    out = []
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        if PRINCIPAL_RE.fullmatch(item):
            out.append(item)
        else:
            logger.error('Ignoring invalid INSPECT_PRINCIPALS entry %r', _printable(item, 80))
    return out


class _JsonHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-store')
        self.clear_header('Server')

    def send_json(self, status, payload):
        self.set_status(status)
        self.finish(json.dumps(payload, separators=(',', ':'), ensure_ascii=False))

    def send_error_body(self, failure):
        err = {'code': failure.code, 'message': failure.message}
        if failure.retry_after is not None:
            err['retryAfter'] = failure.retry_after
        self.send_json(STATUS[failure.code], {'v': WIRE_VERSION, 'error': err})

    def write_error(self, status_code, **kwargs):
        code = {404: 'not_found', 401: 'no_user', 403: 'forbidden'}.get(status_code,
                                                                       'invalid' if status_code < 500 else 'internal')
        self.set_status(status_code)
        self.finish(json.dumps({'v': WIRE_VERSION, 'error': {'code': code, 'message': self._reason}}, ensure_ascii=False))


class NotFoundHandler(_JsonHandler):
    def prepare(self):
        raise tornado.web.HTTPError(404, reason='Not found')


class HealthHandler(_JsonHandler):
    def get(self):
        self.send_json(200, {'ok': True})


class OpHandler(_JsonHandler):
    def initialize(self, runner, principals):
        self.runner = runner
        self.principals = frozenset('spiffe://' + p for p in principals)

    def _check_peer(self):
        uris = xfcc_uris(self.request.headers.get_list(XFCC_HEADER))
        if not any(u in self.principals for u in uris):
            raise Failure('forbidden', 'This caller may not use the inspect port.')

    def _user(self):
        email = wg_mode.normalize_email(self.request.headers.get(USER_HEADER))
        if email is None:
            raise Failure('no_user', 'The X-Inspect-User header is missing or invalid.')
        return email

    def _body(self):
        ctype = (self.request.headers.get('Content-Type') or '').split(';')[0].strip().lower()
        if ctype != 'application/json':
            raise Failure('invalid', 'The content type must be application/json.')
        raw = self.request.body
        if len(raw) > MAX_BODY:
            raise Failure('invalid', 'The body is too large.')
        def refuse(_):
            raise ValueError('constant')
        try:
            return json.loads(raw.decode('utf-8'), parse_constant=refuse)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise Failure('invalid', 'The body is not valid JSON.')

    async def post(self):
        started = time.monotonic()
        rid = self.request.headers.get(REQUEST_ID_HEADER, '')
        rid = rid if REQUEST_ID_RE.fullmatch(rid) else '-'
        info = {'op': '-', 'user': '-', 'ns': '-', 'target': '-'}
        nbytes = 0
        try:
            self._check_peer()
            info['user'] = self._user()
            req = parse_request(self._body())
            info.update(op=req.op, ns=req.namespace, target=req.target)
            result, nbytes = await self.runner.execute(info['user'], req)
            ms = int((time.monotonic() - started) * 1000)
            self._audit(info, 'ok', ms, nbytes, rid, logging.INFO)
            self.send_json(200, {'v': WIRE_VERSION, 'op': req.op, 'ms': ms, 'result': result})
        except Failure as f:
            self._audit(info, f.code, int((time.monotonic() - started) * 1000), nbytes, rid, logging.WARNING)
            self.send_error_body(f)
        except Exception:
            logger.exception('inspect op=%s failed', info['op'])
            self._audit(info, 'internal', int((time.monotonic() - started) * 1000), nbytes, rid, logging.ERROR)
            self.send_error_body(Failure('internal', 'Something went wrong in the inspect pod.'))

    @staticmethod
    def _audit(info, result, ms, nbytes, rid, level):
        # No content, ever: the fields are validated names.
        logger.log(level, 'inspect op=%s user=%s ns=%s target=%s result=%s ms=%d bytes=%d reqId=%s',
                   info['op'], info['user'], info['ns'], info['target'], result, ms, nbytes, rid)


def make_inspect_app(config, principals, runner=None, **runner_kwargs):
    """The inspect Application. `principals`: SPIFFE identities without the scheme."""
    runner = runner or InspectRunner(config, **runner_kwargs)
    app = tornado.web.Application(
        [(re.escape(INSPECT_PATH), OpHandler, {'runner': runner, 'principals': list(principals)}),
         (re.escape(HEALTH_PATH), HealthHandler)],
        default_handler_class=NotFoundHandler)
    app.settings['inspect_runner'] = runner
    return app


def start_inspect_listener(config, principals, port, **runner_kwargs):
    """Start the 8091 listener and the sweeper; returns (application, sweeper) or None when disabled."""
    if not principals:
        return None
    if _YAML_LOADER is None:
        # Release manifests are redacted by parsing them: only with libyaml's parser, never the
        # pure-Python one, so without it nothing is served.
        logger.error("Inspect API not started: PyYAML was built without libyaml (CSafeLoader)")
        return None
    app = make_inspect_app(config, principals, **runner_kwargs)
    app.listen(port, address='0.0.0.0', max_body_size=LISTEN_MAX_BODY)
    sweeper = tornado.ioloop.PeriodicCallback(app.settings['inspect_runner'].sweep, 1000 * SWEEP_INTERVAL)
    sweeper.start()
    return app, sweeper
