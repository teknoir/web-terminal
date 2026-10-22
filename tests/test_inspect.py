import asyncio
import base64
import gzip
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tracemalloc
import unittest

import tornado.web
from tornado.httpclient import AsyncHTTPClient
from tornado.testing import AsyncHTTPTestCase, AsyncTestCase, bind_unused_port, gen_test

import inspect_ops
import named
import wg_mode

ALICE = 'alice@example.com'
BOB = 'bob@example.com'
PRINCIPAL = 'cluster.local/ns/teknoir-system/sa/backstage-api'
XFCC_OK = 'By=spiffe://cluster.local/ns/x/sa/y;Hash=abc;Subject="";URI=spiffe://' + PRINCIPAL

# A stand-in for ssh. It records its argv (one JSON line per call) and behaves
# like a ControlMaster client according to scenario.json in $FAKE_SSH_DIR.
FAKE_SSH = textwrap.dedent('''\
    #!%(python)s
    import json, os, sys, time
    d = os.environ['FAKE_SSH_DIR']
    argv = sys.argv[1:]
    sc = json.load(open(os.path.join(d, 'scenario.json')))
    cp = argv[argv.index('-S') + 1] if '-S' in argv else None
    entry = {'argv': argv, 'pid': os.getpid(), 'cp_existed': bool(cp and os.path.exists(cp))}
    if argv and ' -f -' in argv[-1] and '-O' not in argv and 'ControlMaster=yes' not in argv:
        import base64
        entry['stdin_b64'] = base64.b64encode(sys.stdin.buffer.read()).decode()
    with open(os.path.join(d, 'calls.jsonl'), 'a') as fh:
        fh.write(json.dumps(entry) + '\\n')
    def finish(rc, out=b'', err=''):
        sys.stdout.buffer.write(out); sys.stdout.buffer.flush()
        sys.stderr.write(err); sys.stderr.flush()
        sys.exit(rc)
    if '-O' in argv:
        what = argv[argv.index('-O') + 1]
        if what == 'check':
            if 'check_rc' in sc:
                finish(sc['check_rc'], err='Control socket connect: No such file or directory\\n')
            finish(0 if os.path.exists(cp) else 255)
        if what == 'exit':
            if os.path.exists(cp):
                os.unlink(cp)
            finish(0)
    if 'ControlMaster=yes' in argv:
        m = sc.get('master', {})
        if m.get('rc', 0) == 0:
            open(cp, 'w').close()
        finish(m.get('rc', 0), err=m.get('stderr', ''))
    remote = argv[-1]
    for op in sc.get('ops', []):
        if op['match'] in remote:
            if op.get('sleep'):
                time.sleep(op['sleep'])
            out = op.get('stdout', '').encode()
            if 'stdout_bytes' in op:
                out = b'x' * op['stdout_bytes']
            finish(op.get('rc', 0), out=out, err=op.get('stderr', ''))
    finish(1, err='fake ssh: no scenario for ' + remote + '\\n')
''')


def make_config():
    return wg_mode.WireGuardConfig(hub_url='http://wg-hub.teknoir-ztna.svc:8081', namespace='teknoir-demo',
                                   device='cam-1', sa_token_file='/var/run/secrets/ztna/token',
                                   remote_username='teknoir', rsa_key_file='/priv.pem')


class FakeSSHMixin:
    def setup_fake(self):
        self.work = tempfile.mkdtemp(prefix='insp-')
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.ssh = os.path.join(self.work, 'ssh')
        with open(self.ssh, 'w') as fh:
            fh.write(FAKE_SSH % {'python': sys.executable})
        os.chmod(self.ssh, 0o755)
        self.base_dir = os.path.join(self.work, 'run')
        os.environ['FAKE_SSH_DIR'] = self.work
        self.scenario({})

    def scenario(self, data):
        with open(os.path.join(self.work, 'scenario.json'), 'w') as fh:
            json.dump(data, fh)

    def calls(self):
        path = os.path.join(self.work, 'calls.jsonl')
        if not os.path.exists(path):
            return []
        return [json.loads(line) for line in open(path)]

    def op_calls(self):
        return [c for c in self.calls() if '-O' not in c['argv'] and 'ControlMaster=yes' not in c['argv']]

    def exit_calls(self):
        return [c for c in self.calls() if '-O' in c['argv'] and c['argv'][c['argv'].index('-O') + 1] == 'exit']

    def master_calls(self):
        return [c for c in self.calls() if 'ControlMaster=yes' in c['argv']]


def helm_release(manifest, version=3, status='deployed', gz=True, extra=None, name='nvr', namespace='teknoir-demo'):
    rel = {
        'name': name, 'namespace': namespace, 'version': version,
        'info': {'first_deployed': '2026-10-01T10:00:00Z', 'last_deployed': '2026-10-02T10:00:00Z',
                 'status': status, 'description': 'Install complete', 'notes': 'SECRET NOTE'},
        'chart': {'metadata': {'name': 'nvr', 'version': '0.4.2', 'appVersion': '1.2.0'},
                  'values': {'password': 'chart-default-pw'},
                  'templates': [{'name': 'templates/x.yaml', 'data': 'AAAA'}]},
        'config': {'dbPassword': 'hunter2'},
        'manifest': manifest,
        'hooks': [{'name': 'hook', 'manifest': 'kind: Job\nenv: secret-hook'}],
    }
    if extra:
        rel.update(extra)
    blob = json.dumps(rel).encode()
    if gz:
        blob = gzip.compress(blob)
    # helm base64, then k8s base64 of that (the Secret's data field)
    return base64.b64encode(base64.b64encode(blob)).decode()


MANIFEST = '''---
# Source: nvr/templates/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: nvr-db
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"data":{"pw":"c3VwZXI="}}'
type: Opaque
data:
  password: aHVudGVyMg==
  user: YWRtaW4=
stringData:
  token: plain-text-token
---
# Source: nvr/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nvr-config
data:
  LOG_LEVEL: info  # keep this comment
---
# Source: nvr/templates/broken.yaml
kind: Secret
data: {unclosed: [
password: leaked-in-broken-doc
---
# Source: nvr/templates/list.yaml
apiVersion: v1
kind: SecretList
items:
  - kind: Secret
    metadata: {name: a}
    data: {k: dmFsdWU=}
  - kind: ConfigMap
    metadata: {name: b}
    data: {k: visible}
'''


def kubectl_out(*objects):
    """What `kubectl create --dry-run=client -o json -f -` prints for several documents: the
    objects one after the other, pretty printed (verified against kubectl 1.35)."""
    return ''.join(json.dumps(o, indent=4) + '\n' for o in objects)


SECRET_OBJ = {'apiVersion': 'v1', 'kind': 'Secret',
              'metadata': {'name': 'nvr-db', 'namespace': 'teknoir-demo', 'annotations': {
                  'kubectl.kubernetes.io/last-applied-configuration': '{"data":{"pw":"c3VwZXI="}}'}},
              'type': 'Opaque', 'data': {'password': 'aHVudGVyMg==', 'user': 'YWRtaW4='},
              'stringData': {'token': 'plain-text-token'}}
CONFIGMAP_OBJ = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                 'metadata': {'name': 'nvr-config', 'namespace': 'teknoir-demo'}, 'data': {'LOG_LEVEL': 'info'}}
KUBECTL_OK = kubectl_out(SECRET_OBJ, CONFIGMAP_OBJ)
CREATE = 'create --dry-run=client'      # matches the manifest decode command in the fake ssh scenarios




class TestValidation(unittest.TestCase):
    def ok(self, **body):
        return inspect_ops.parse_request(dict({'v': 1}, **body))

    def bad(self, msg=None, **body):
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.parse_request(dict({'v': 1}, **body))
        self.assertEqual(cm.exception.code, 'invalid', msg)

    def test_good_requests(self):
        self.ok(op='pod', namespace='teknoir-demo', pod='nvr-7d9f-abcde')
        self.ok(op='events', namespace='a', pod='p.1-x')
        r = self.ok(op='logs', namespace='ns', pod='p', container='c-1', previous=True, tail=2000, since='168h')
        self.assertEqual(r.target, 'ns/p/c-1')
        self.ok(op='logs', namespace='ns', pod='p', since='90s')
        r = self.ok(op='release', namespace='ns', release='nvr', revision=999999)
        self.assertEqual(r.target, 'ns/nvr@999999')

    def test_namespace_pod_container_release_table(self):
        for field, op, extra in (('namespace', 'pod', {'pod': 'p'}), ('pod', 'pod', {'namespace': 'n'}),
                                 ('container', 'logs', {'namespace': 'n', 'pod': 'p'}),
                                 ('release', 'release', {'namespace': 'n'})):
            long_ok = {'namespace': 'a' * 63, 'pod': 'a' * 253, 'container': 'a' * 63,
                       'release': 'a' * 53}[field]
            self.ok(op=op, **dict(extra, **{field: long_ok}))
            too_long = {'namespace': 'a' * 64, 'pod': 'a' * 254, 'container': 'a' * 64,
                        'release': 'a' * 54}[field]
            for bad in ('-n', '-', 'Upper', 'a b', 'a;b', 'a$(id)b', 'a"b', "a'b", 'a\nb', 'a\n', 'é',
                        '', ' a', 'a/b', 'a`b`', '--all-namespaces', too_long, 5, None, ['a']):
                if field == 'pod' and bad == 'a/b':
                    pass
                self.bad('%s=%r' % (field, bad), op=op, **dict(extra, **{field: bad}))
        # the pod pattern allows dots, the others do not
        self.ok(op='pod', namespace='n', pod='a.b')
        self.bad(op='pod', namespace='a.b', pod='p')
        self.bad(op='release', namespace='n', release='a.b')
        self.bad(op='logs', namespace='n', pod='p', container='a.b')

    def test_tail_since_revision_previous(self):
        base = {'op': 'logs', 'namespace': 'n', 'pod': 'p'}
        for tail in (0, -1, 2001, 1.5, 500.0, True, '500', None):
            self.bad('tail=%r' % (tail,), tail=tail, **base)
        for since in ('0s', '1d', '5', 'h', '169h', '10081m', '604801s', '1H', ' 1h', '1h\n', '+5m', '5.5m',
                      '1234567s', 5, True):
            self.bad('since=%r' % (since,), since=since, **base)
        for prev in (1, 0, 'true', None, 'yes'):
            self.bad('previous=%r' % (prev,), previous=prev, **base)
        rel = {'op': 'release', 'namespace': 'n', 'release': 'r'}
        for rev in (0, -3, 1000000, 1.0, True, '3', None):
            self.bad('revision=%r' % (rev,), revision=rev, **rel)

    def test_envelope(self):
        self.bad(op='nope', namespace='n', pod='p')
        self.bad(op='exec', namespace='n', pod='p')
        self.bad(op=['pod'], namespace='n', pod='p')
        self.bad(namespace='n', pod='p')
        self.bad(op='pod', namespace='n')          # missing pod
        self.bad(op='pod', pod='p')                # missing namespace
        self.bad(op='release', namespace='n')      # missing release
        self.bad(op='pod', namespace='n', pod='p', extra=1)            # unknown key
        self.bad(op='pod', namespace='n', pod='p', tail=5)             # field of another op
        self.bad(op='events', namespace='n', pod='p', container='c')
        self.bad(op='release', namespace='n', release='r', pod='p')
        for v in (0, 2, '1', 1.0, True, None):
            with self.assertRaises(inspect_ops.Failure):
                inspect_ops.parse_request({'v': v, 'op': 'pod', 'namespace': 'n', 'pod': 'p'})
        for body in ([], 'pod', 5, None):
            with self.assertRaises(inspect_ops.Failure):
                inspect_ops.parse_request(body)


class TestCommands(unittest.TestCase):
    def cmd(self, **body):
        req = inspect_ops.parse_request(dict({'v': 1}, **body))
        return inspect_ops.remote_command(inspect_ops.kubectl_argv(req))

    K = 'sudo -n k3s kubectl --request-timeout=15s'

    def test_pod_and_events(self):
        self.assertEqual(self.cmd(op='pod', namespace='teknoir-demo', pod='nvr-1'),
                         self.K + ' -n teknoir-demo get pod nvr-1 -o json')
        self.assertEqual(self.cmd(op='events', namespace='teknoir-demo', pod='nvr-1'),
                         self.K + ' -n teknoir-demo get events --field-selector '
                         'involvedObject.kind=Pod,involvedObject.name=nvr-1 -o json')

    def test_logs_golden(self):
        self.assertEqual(
            self.cmd(op='logs', namespace='teknoir-demo', pod='nvr-7d9f-abcde', container='nvr', previous=True),
            'sudo -n k3s kubectl --request-timeout=15s -n teknoir-demo logs nvr-7d9f-abcde -c nvr --previous '
            '--tail=500 --timestamps --limit-bytes=1048576')
        self.assertEqual(
            self.cmd(op='logs', namespace='n', pod='p', tail=20, since='1h'),
            self.K + ' -n n logs p --tail=20 --since=1h --timestamps --limit-bytes=1048576')

    def test_release(self):
        req = inspect_ops.parse_request({'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr'})
        listing = inspect_ops.remote_command(inspect_ops.kubectl_argv(req))
        self.assertEqual(listing, self.K + " -n n get secrets -l owner=helm,name=nvr -o "
                         "'jsonpath={range .items[*]}{.metadata.labels.version}{\"\\t\"}"
                         "{.metadata.labels.status}{\"\\n\"}{end}'")
        read = inspect_ops.remote_command(inspect_ops.kubectl_argv(req, 7))
        self.assertEqual(read, self.K + " -n n get secret sh.helm.release.v1.nvr.v7 -o 'jsonpath={.data.release}'")

    def test_remote_command_is_one_shell_word_list(self):
        # whatever the values, the remote command splits back into the same argv
        req = inspect_ops.parse_request({'v': 1, 'op': 'logs', 'namespace': 'n', 'pod': 'a.b-c', 'tail': 5})
        argv = inspect_ops.kubectl_argv(req)
        self.assertEqual(shlex.split(inspect_ops.remote_command(argv)), argv)


class TestStderrMapping(unittest.TestCase):
    def f(self, text, rc=1, connection=False):
        return inspect_ops.classify_failure(text, rc, connection)

    def test_rows(self):
        cases = [
            ('access denied: session_limit (too many sessions)', 255, 'session_limit', 429),
            ('access denied: forbidden (this device is outside your organisation units)', 255, 'forbidden', 403),
            ('access denied: unauthenticated (bad token)', 255, 'forbidden', 403),
            ('access denied: device_offline (last seen 5m ago)', 255, 'offline', 503),
            ('access denied: device_disabled', 255, 'offline', 503),
            ('access denied: device_revoked (x)', 255, 'offline', 503),
            ('access denied: device_unknown (x)', 255, 'offline', 503),
            ('access denied: posture (x)', 255, 'offline', 503),
            ('access denied: port_not_allowed (x)', 255, 'offline', 503),
            ('access denied: rate_limited (x)', 255, 'busy', 429),
            ('access denied: something_new (x)', 255, 'unavailable', 503),
            ('ssh: connect to host x port 22: Connection refused', 255, 'unavailable', 503),
            ('Error from server (BadRequest): previous terminated container "nvr" in pod "p" not found',
             1, 'no_previous', 404),
            ('Error from server (BadRequest): container "nvr" in pod "p" is waiting to start: ContainerCreating',
             1, 'not_started', 409),
            ('container "x" in pod "p" is waiting to start: PodInitializing', 1, 'not_started', 409),
            ('Error from server (NotFound): pods "p" not found', 1, 'not_found', 404),
            ('Error from server (NotFound): namespaces "zz" not found', 1, 'not_found', 404),
            ('sudo: a password is required', 1, 'device_error', 502),
            ('sudo: k3s: command not found', 1, 'device_error', 502),
            ('bash: line 1: k3s: command not found', 127, 'device_error', 502),
            ('Error from server (Forbidden): pods is forbidden', 1, 'device_error', 502),
            ('', 1, 'device_error', 502),
        ]
        for text, rc, code, status in cases:
            failure = self.f(text, rc)
            self.assertEqual(failure.code, code, text)
            self.assertEqual(inspect_ops.STATUS[failure.code], status, text)
        self.assertEqual(self.f('access denied: rate_limited (x)', 255).retry_after, 5)

    def test_offline_names_the_reason_and_forbidden_keeps_hub_text(self):
        self.assertIn('device_offline', self.f('access denied: device_offline (x)', 255).message)
        self.assertEqual(self.f('access denied: forbidden (outside your units)', 255).message, 'outside your units')
        self.assertEqual(self.f('sudo: a password is required').message,
                         'The device login user cannot run kubectl through sudo.')

    def test_master_start_nonzero_is_connection_level(self):
        self.assertEqual(self.f('Host key verification failed.', 1, connection=True).code, 'unavailable')
        self.assertEqual(self.f('access denied: forbidden (x)', 1, connection=True).code, 'forbidden')

    def test_denial_detail_keeps_parentheses_inside_it(self):
        self.assertEqual(self.f('access denied: forbidden (outside (unit a) here)', 255).message,
                         'outside (unit a) here')

    def test_denial_pattern_is_linear_on_repeated_openers(self):
        # an unbounded `(.*?)` was tried from every opener and ran to the end of the line each time
        text = ('access denied: a (' * 1000)[:16 * 1024]
        for fn in (lambda: inspect_ops._DENIED_RE.search(text),
                   lambda: inspect_ops.manifest_failure(text, 255),
                   lambda: inspect_ops.classify_failure(text, 255)):
            best = min(self.timed(fn) for _ in range(3))
            self.assertLess(best, 0.02, best)
        spaced = ('access denied: a (' + ' ' * 40) * 400
        self.assertLess(min(self.timed(lambda: inspect_ops._DENIED_RE.search(spaced)) for _ in range(3)), 0.02)

    @staticmethod
    def timed(fn):
        started = time.perf_counter()
        fn()
        return time.perf_counter() - started

    def test_device_output_cannot_fake_a_hub_denial(self):
        # kubectl exit 1 printing "access denied: forbidden" is a device_error, not a hub answer
        self.assertEqual(self.f('access denied: forbidden (x)', 1).code, 'device_error')

    def test_first_line_is_cut_and_cleaned(self):
        failure = self.f('\x1b[31m' + 'e' * 500 + '\nsecond line', 1)
        self.assertEqual(failure.code, 'device_error')
        self.assertLessEqual(len(failure.message), 300)
        self.assertNotIn('\x1b', failure.message)
        self.assertNotIn('second', failure.message)


class TestShaping(unittest.TestCase):
    def test_prune_pod(self):
        pod = {
            'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'p', 'namespace': 'n', 'uid': 'u', 'creationTimestamp': 't',
                         'labels': {'a': 'b'}, 'annotations': {'big': 'x'}, 'managedFields': [{'x': 1}],
                         'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'rs', 'uid': 'z', 'controller': True}]},
            'spec': {'nodeName': 'node', 'restartPolicy': 'Always', 'serviceAccountName': 'sa',
                     'priorityClassName': 'pc', 'tolerations': [1], 'hostNetwork': True,
                     'containers': [{
                         'name': 'c', 'image': 'i', 'imagePullPolicy': 'Always', 'command': ['run'],
                         'args': ['--x'], 'ports': [{'containerPort': 80}], 'resources': {'limits': {'memory': '1Gi'}},
                         'env': [{'name': 'DB_PASSWORD', 'value': 'hunter2'}, {'name': 'MODE', 'value': 'fast'},
                                 {'name': 'API_TOKEN', 'valueFrom': {'secretKeyRef': {'name': 's', 'key': 'k'}}},
                                 {'name': 'AUTHOR', 'value': 'someone'}],
                         'envFrom': [{'secretRef': {'name': 's'}}],
                         'volumeMounts': [{'name': 'v', 'mountPath': '/m', 'readOnly': True, 'subPath': 'x'}],
                         'livenessProbe': {'httpGet': {}}, 'securityContext': {'privileged': True}}],
                     'initContainers': [{'name': 'init', 'image': 'i2'}],
                     'volumes': [{'name': 'v', 'secret': {'secretName': 's'}}, {'name': 'w', 'emptyDir': {}}]},
            'status': {'phase': 'Running', 'qosClass': 'Burstable', 'podIP': '10.0.0.1', 'hostIPs': [1],
                       'conditions': [{'type': 'Ready'}], 'containerStatuses': [{'name': 'c', 'restartCount': 3}],
                       'initContainerStatuses': []},
        }
        out = inspect_ops.prune_pod(pod)
        self.assertEqual(out['metadata'], {
            'name': 'p', 'namespace': 'n', 'uid': 'u', 'creationTimestamp': 't', 'labels': {'a': 'b'},
            'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'rs'}]})
        self.assertEqual(out['spec']['volumes'], [{'name': 'v', 'type': 'secret'}, {'name': 'w', 'type': 'emptyDir'}])
        self.assertNotIn('tolerations', out['spec'])
        self.assertNotIn('hostNetwork', out['spec'])
        c = out['spec']['containers'][0]
        self.assertEqual(set(c), {'name', 'image', 'imagePullPolicy', 'command', 'args', 'ports', 'resources',
                                  'env', 'envFrom', 'volumeMounts'})
        env = {e['name']: e.get('value') for e in c['env']}
        self.assertEqual(env['DB_PASSWORD'], '<hidden>')
        self.assertEqual(env['MODE'], 'fast')
        self.assertEqual(env['AUTHOR'], 'someone')                 # `auth(?!ors?)` does not hide authors
        self.assertNotIn('value', [e for e in c['env'] if e['name'] == 'API_TOKEN'][0])
        self.assertEqual(c['volumeMounts'], [{'name': 'v', 'mountPath': '/m', 'readOnly': True}])
        self.assertEqual(out['spec']['initContainers'], [{'name': 'init', 'image': 'i2'}])
        self.assertNotIn('hostIPs', out['status'])
        self.assertEqual(out['status']['containerStatuses'], [{'name': 'c', 'restartCount': 3}])
        self.assertNotIn('hunter2', json.dumps(out))

    def test_secret_key_regex(self):
        for name in ('PASSWORD', 'db_pass', 'MY_SECRET', 'GITHUB_TOKEN', 'API_KEY', 'api-key', 'PRIVATE_KEY',
                     'CREDENTIALS', 'SENTRY_DSN', 'PWD', 'AUTH_HEADER', 'oauth_x'):
            self.assertTrue(inspect_ops.SECRET_KEY.search(name), name)
        for name in ('BYPASS', 'COMPASS', 'PASSTHROUGH', 'AUTHOR', 'AUTHORS', 'MODE', 'LOG_LEVEL'):
            self.assertFalse(inspect_ops.SECRET_KEY.search(name), name)

    def test_prune_pod_garbage(self):
        with self.assertRaises(inspect_ops.Failure):
            inspect_ops.prune_pod([])
        self.assertEqual(inspect_ops.prune_pod({'metadata': 5, 'spec': [], 'status': None}),
                         {'metadata': {}, 'spec': {}, 'status': {}})

    def test_events(self):
        items = [{'type': 'Warning', 'reason': 'BackOff', 'message': 'm' * 3000, 'count': 5,
                  'firstTimestamp': '2026-10-22T10:00:00Z', 'lastTimestamp': '2026-10-22T10:05:00Z',
                  'source': {'component': 'kubelet'}},
                 {'type': 'Normal', 'reason': 'Pulled', 'message': 'ok', 'series': {'count': 9,
                  'lastObservedTime': '2026-10-22T10:01:00Z'}, 'eventTime': '2026-10-22T09:59:00Z',
                  'reportingController': 'kubelet-x'}]
        out = inspect_ops.shape_events({'items': items})
        self.assertEqual([e['reason'] for e in out['events']], ['Pulled', 'BackOff'])      # by last ascending
        self.assertEqual(out['events'][0], {'type': 'Normal', 'reason': 'Pulled', 'message': 'ok', 'count': 9,
                                            'first': '2026-10-22T09:59:00Z', 'last': '2026-10-22T10:01:00Z',
                                            'source': 'kubelet-x'})
        self.assertEqual(len(out['events'][1]['message']), 1024)
        self.assertFalse(out['truncated'])

    def test_events_newest_200_kept(self):
        items = [{'reason': 'r%d' % i, 'lastTimestamp': '2026-10-22T10:%02d:%02dZ' % (i // 60, i % 60)}
                 for i in range(250)]
        out = inspect_ops.shape_events({'items': items})
        self.assertTrue(out['truncated'])
        self.assertEqual(len(out['events']), 200)
        self.assertEqual(out['events'][-1]['reason'], 'r249')
        self.assertEqual(out['events'][0]['reason'], 'r50')

    def test_events_streaming_matches_sorting_everything(self):
        import random
        rnd = random.Random(7)
        for n in (0, 1, 199, 200, 201, 700):
            items = [{'reason': 'r%d' % i, 'type': 'Normal',
                      'lastTimestamp': '2026-10-22T10:%02d:00Z' % rnd.randrange(0, 4)} for i in range(n)]
            items += [3, None, 'x']                       # not events: skipped, not counted
            out = inspect_ops.shape_events({'items': items})
            rows = [{'type': 'Normal', 'reason': e['reason'], 'message': None, 'count': None, 'first': None,
                     'last': e['lastTimestamp'], 'source': None} for e in items if isinstance(e, dict)]
            rows.sort(key=lambda r: str(r['last'] or ''))       # the old, stable, build-everything way
            self.assertEqual(out['events'], rows[-200:], n)
            self.assertEqual(out['truncated'], n > 200, n)

    def test_events_rows_are_built_only_for_what_can_be_kept(self):
        built = []

        class Spy(dict):
            def get(self, key, default=None):
                if key == 'message':
                    built.append(1)
                return dict.get(self, key, default)
        items = [Spy(reason='r%d' % i, lastTimestamp='2026-10-22T10:%02d:%02dZ' % (i // 60, i % 60))
                 for i in range(2000)]
        items.reverse()                                       # oldest last: nothing after the first 200 qualifies
        inspect_ops.shape_events({'items': items})
        self.assertEqual(len(built), 200)

    def test_events_and_pod_shaping_stop_at_the_deadline(self):
        past = time.monotonic() - 1
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.shape_events({'items': [{'reason': 'x'}]}, deadline=past)
        self.assertEqual(cm.exception.code, 'too_large')
        for fn in (inspect_ops.shape_pod_json, inspect_ops.shape_events_json):
            with self.assertRaises(inspect_ops.Failure) as cm:
                fn(b'{"items": []}', past)
            self.assertEqual(cm.exception.code, 'too_large')

    def test_json_container_bound_is_checked_before_parsing(self):
        orig = inspect_ops.json.loads

        def boom(*a, **k):
            raise AssertionError('parsed')
        inspect_ops.json.loads = boom
        try:
            with self.assertRaises(inspect_ops.Failure) as cm:
                inspect_ops._json(b'[' + b'{},' * 20 + b'{}]', 10)
            self.assertEqual(cm.exception.code, 'too_large')
        finally:
            inspect_ops.json.loads = orig
        self.assertEqual(inspect_ops._json(b'[{},{}]', 10), [{}, {}])

    def req_logs(self, **kw):
        return inspect_ops.parse_request(dict({'v': 1, 'op': 'logs', 'namespace': 'n', 'pod': 'p'}, **kw))

    def test_logs_flags(self):
        out = inspect_ops.shape_logs(b'a\nb\nc\n', b'', self.req_logs(tail=3), False)
        self.assertEqual((out['lines'], out['bytes'], out['truncated']), (3, 6, {'bytes': False, 'lines': True}))
        out = inspect_ops.shape_logs(b'a\nb\nc', b'Defaulted container "nvr" out of: nvr, side\n', self.req_logs(), False)
        self.assertEqual((out['lines'], out['container'], out['previous']), (3, 'nvr', False))
        out = inspect_ops.shape_logs(b'', b'', self.req_logs(container='c', previous=True), False)
        self.assertEqual((out['lines'], out['container'], out['previous']), (0, 'c', True))
        self.assertIsNone(inspect_ops.shape_logs(b'x', b'', self.req_logs(), False)['container'])

    def test_logs_byte_cap(self):
        line = b'0123456789' * 9 + b'012345678\n'      # 100 bytes
        raw = (line * 10500)[:inspect_ops.LOG_LIMIT_BYTES]
        out = inspect_ops.shape_logs(raw, b'', self.req_logs(), False)
        self.assertTrue(out['truncated']['bytes'])
        self.assertTrue(out['text'].endswith('\n'))
        self.assertLessEqual(out['bytes'], inspect_ops.LOG_LIMIT_BYTES)
        # the read cap was hit (process killed): same flag, never more than 1 MiB
        out = inspect_ops.shape_logs(line * 11000, b'', self.req_logs(), True)
        self.assertTrue(out['truncated']['bytes'])
        self.assertLessEqual(out['bytes'], inspect_ops.LOG_LIMIT_BYTES)

    def test_logs_binary_output_stays_within_contract(self):
        out = inspect_ops.shape_logs(b'\xff' * (1 << 20), b'', self.req_logs(), False)
        self.assertLessEqual(out['bytes'], inspect_ops.LOG_LIMIT_BYTES)
        self.assertLessEqual(len(out['text'].encode('utf-8')), inspect_ops.LOG_LIMIT_BYTES)
        self.assertTrue(out['truncated']['bytes'])

    def test_logs_invalid_utf8_replaced(self):
        out = inspect_ops.shape_logs(b'ok \xff\xfe\n', b'', self.req_logs(), False)
        self.assertIn('ok ', out['text'])


class TestRelease(unittest.TestCase):
    # --- kubectl's JSON -> objects: Secret redaction on JSON, never on YAML (plans/nextgen/inspect.md 3.4) ---

    KEPT = {'status': 'deployed', 'chart': 'nvr', 'chartVersion': '0.4.2', 'appVersion': '1.2.0',
            'last_deployed': '2026-10-02T10:00:00Z'}
    ROWS = [(3, 'deployed'), (2, 'superseded')]

    def shape(self, out, rc=0, err=b'', **kw):
        if isinstance(out, str):
            out = out.encode()
        if isinstance(err, str):
            err = err.encode()
        return inspect_ops.shape_release_objects(self.KEPT, self.ROWS, 'nvr', 'teknoir-demo', 3, rc, out, err, **kw)

    def objects(self, *objs):
        return self.shape(kubectl_out(*objs))['objects']

    def test_response_shape(self):
        out = self.shape(KUBECTL_OK)
        self.assertEqual(list(out), ['name', 'namespace', 'revision', 'status', 'chart', 'chartVersion',
                                     'objects', 'hidden', 'history', 'appVersion', 'lastDeployed'])
        self.assertEqual((out['name'], out['namespace'], out['revision'], out['status'], out['chart'],
                          out['chartVersion'], out['appVersion'], out['lastDeployed']),
                         ('nvr', 'teknoir-demo', 3, 'deployed', 'nvr', '0.4.2', '1.2.0', '2026-10-02T10:00:00Z'))
        self.assertEqual(out['hidden'], [])
        self.assertEqual(out['history'], [{'revision': 3, 'status': 'deployed'},
                                          {'revision': 2, 'status': 'superseded'}])
        self.assertNotIn('manifest', out)
        self.assertEqual(len(out['objects']), 2)
        self.assertEqual(out['objects'][1], CONFIGMAP_OBJ)          # other kinds are returned as they are
        self.assertTrue(json.dumps(out))

    def test_a_secret_shows_only_its_allowed_fields(self):
        secret = self.objects(dict(SECRET_OBJ, binaryData={'b': 'QUJD'}, immutable=True,
                                   foo='LEAK-top', Data={'x': 'LEAK-case'}))[0]
        self.assertEqual(secret, {
            'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'nvr-db', 'namespace': 'teknoir-demo'},
            'type': 'Opaque', 'immutable': True,
            'data': {'password': '<hidden>', 'user': '<hidden>'}, 'stringData': {'token': '<hidden>'},
            'binaryData': {'b': '<hidden>'}})
        self.assertNotIn('LEAK', json.dumps(secret))

    def test_secret_metadata_drops_managed_fields_and_last_applied_in_any_case(self):
        meta = {'name': 'n', 'managedFields': [{'fieldsV1': {'f:data': {'f:pw': {}}}, 'manager': 'x'}],
                'ManagedFields': 'LEAK', 'labels': {'a': 'b'},
                'annotations': {'Kubectl.Kubernetes.io/Last-Applied-Configuration': 'LEAK',
                                'note': 'keep'}}
        secret = self.objects({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': meta})[0]
        self.assertEqual(secret['metadata'], {'name': 'n', 'labels': {'a': 'b'}, 'annotations': {'note': 'keep'}})
        only = self.objects({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
            'name': 'n', 'annotations': {'kubectl.kubernetes.io/last-applied-configuration': 'LEAK'}}})[0]
        self.assertEqual(only['metadata'], {'name': 'n'})

    def test_kind_is_compared_case_insensitively_and_trimmed(self):
        for kind in ('secret', 'SECRET', 'sEcReT', ' Secret ', 'Secret\t'):
            obj = self.objects({'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': 'n'},
                                'data': {'k': 'LEAK'}, 'extra': 'LEAK'})[0]
            self.assertEqual(obj['data'], {'k': '<hidden>'}, repr(kind))
            self.assertNotIn('LEAK', json.dumps(obj), repr(kind))
            self.assertNotIn('extra', obj)

    def test_a_secret_of_any_apiversion_is_reduced(self):
        obj = self.objects({'apiVersion': 'v2', 'kind': 'Secret', 'data': {'k': 'LEAK'}})[0]
        self.assertEqual(obj['data'], {'k': '<hidden>'})

    def test_a_secret_with_odd_values_for_its_fields(self):
        obj = self.objects({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': 'LEAK-meta',
                            'type': {'LEAK': 1}, 'immutable': ['LEAK'], 'data': 'LEAK-text',
                            'stringData': ['LEAK'], 'binaryData': None})[0]
        self.assertEqual(obj, {'apiVersion': 'v1', 'kind': 'Secret', 'data': '<hidden>',
                               'stringData': '<hidden>', 'binaryData': '<hidden>'})

    def test_a_secret_keeps_type_only_as_a_string_and_immutable_only_as_a_boolean(self):
        for field, value, kept in (('type', 'Opaque', True), ('type', '', True), ('type', 5, False),
                                   ('type', True, False), ('type', None, False), ('type', 1.5, False),
                                   ('immutable', True, True), ('immutable', False, True),
                                   ('immutable', 1, False), ('immutable', 0, False),
                                   ('immutable', 'true', False), ('immutable', None, False),
                                   ('immutable', 1.0, False)):
            obj = self.objects({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'n'},
                                field: value})[0]
            if kept:
                self.assertEqual(obj[field], value, (field, value))
                self.assertIs(type(obj[field]), type(value))
            else:
                self.assertNotIn(field, obj, (field, value))
        # apiVersion and kind still pass as plain scalars only
        obj = inspect_ops.secret_view({'apiVersion': {'LEAK': 1}, 'kind': 'Secret'})
        self.assertEqual(obj, {'kind': 'Secret'})

    def test_compact_json_size_is_exactly_what_json_dumps_gives(self):
        samples = [{}, [], '', {'a': {}}, [[], {}], 1e999, float('nan'), -0.0, 10 ** 40, True, None,
                   {'k': [1, 2.5, True, False, None, 'e\u00e9\u2028\n"\\\x01\x7f\U0001F600\ud800']},
                   {'\u00e9\U0001F600': 'x' * 200000 + '\U0001F600\n'}, ['a' * 70000 + '\n' * 70000]]
        for value in samples:
            want = len(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf-8', 'replace'))
            self.assertEqual(inspect_ops.compact_json_size(value, 10 ** 12), want, repr(value)[:60])
        # it stops as soon as the limit is passed
        self.assertGreater(inspect_ops.compact_json_size({'a': ['x' * 100] * 100}, 500), 500)

    def test_a_secret_value_never_reaches_the_result_in_any_position(self):
        out = self.shape(kubectl_out(SECRET_OBJ, CONFIGMAP_OBJ, {'apiVersion': 'v1', 'kind': 'List', 'items': [
            SECRET_OBJ, {'apiVersion': 'v1', 'kind': 'List', 'items': [SECRET_OBJ]}]}))
        blob = json.dumps(out)
        for leaked in ('aHVudGVyMg', 'YWRtaW4', 'plain-text-token', 'c3VwZXI', 'last-applied'):
            self.assertNotIn(leaked, blob)
        self.assertEqual([o['kind'] for o in out['objects']], ['Secret', 'ConfigMap', 'Secret', 'Secret'])

    def test_lists_are_flattened_nested_ones_too(self):
        inner = {'apiVersion': 'v1', 'kind': 'List', 'items': [CONFIGMAP_OBJ]}
        out = self.shape(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [SECRET_OBJ, inner, inner]}))
        self.assertEqual([o['kind'] for o in out['objects']], ['Secret', 'ConfigMap', 'ConfigMap'])
        self.assertEqual(out['objects'][0]['data'], {'password': '<hidden>', 'user': '<hidden>'})
        # an empty List
        self.assertEqual(self.shape('{"apiVersion":"v1","kind":"List","items":[]}')['objects'], [])

    def test_any_object_with_an_items_array_is_flattened_like_kubectl_does(self):
        out = self.shape(json.dumps({'apiVersion': 'v1', 'kind': 'SecretList', 'items': [SECRET_OBJ]}))
        self.assertEqual(len(out['objects']), 1)
        self.assertEqual(out['objects'][0]['data'], {'password': '<hidden>', 'user': '<hidden>'})
        out = self.shape(json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap', 'data': {'LEAK': 'x'},
                                     'items': [CONFIGMAP_OBJ]}))
        self.assertEqual(out['objects'], [CONFIGMAP_OBJ])        # the wrapper is not shown, only its members

    def test_lists_nested_too_deep_are_hidden(self):
        value = SECRET_OBJ
        for _ in range(inspect_ops.MAX_LIST_DEPTH + 3):
            value = {'apiVersion': 'v1', 'kind': 'List', 'items': [value]}
        out = self.shape(json.dumps(value))
        self.assertEqual(out['objects'], [])
        self.assertEqual(len(out['hidden']), 1)
        self.assertNotIn('aHVudGVyMg', json.dumps(out))

    def test_one_object_a_list_or_a_stream_of_objects(self):
        for text in (json.dumps(CONFIGMAP_OBJ), json.dumps(CONFIGMAP_OBJ, indent=4),
                     json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [CONFIGMAP_OBJ]}),
                     '  \n' + kubectl_out(CONFIGMAP_OBJ) + '\n\n'):
            self.assertEqual(self.shape(text)['objects'], [CONFIGMAP_OBJ], text)
        self.assertEqual(len(self.shape(kubectl_out(*[CONFIGMAP_OBJ] * 50))['objects']), 50)

    def test_things_that_are_not_objects_are_hidden(self):
        out = self.shape('[1, 2] "text" 7 {"kind": 7, "data": {"k": "LEAK"}} {"data": {"k": "LEAK"}} '
                         + json.dumps(CONFIGMAP_OBJ))
        self.assertEqual(out['objects'], [CONFIGMAP_OBJ])
        self.assertEqual(len(out['hidden']), 2)
        self.assertNotIn('LEAK', json.dumps(out))

    def test_partial_output_with_a_nonzero_exit_reports_what_failed(self):
        err = ('error: resource mapping not found for name: "c" namespace: "" from "STDIN": no matches for '
               'kind "Foo" in version "x/v1"\nensure CRDs are installed first\n'
               'E1022 14:42:47.951670 1957530 memcache.go:265] "Unhandled Error" err="LEAK-noise"\n')
        out = self.shape(kubectl_out(SECRET_OBJ, CONFIGMAP_OBJ), rc=1, err=err)
        self.assertEqual([o['kind'] for o in out['objects']], ['Secret', 'ConfigMap'])
        self.assertEqual(out['hidden'], [
            {'reason': 'an object of the unknown kind Foo (its CRD is not installed on the robot)'}])
        self.assertNotIn('LEAK', json.dumps(out))
        # no error line at all
        out = self.shape(kubectl_out(CONFIGMAP_OBJ), rc=1)
        self.assertEqual(out['hidden'], [{'reason': 'kubectl stopped before the end of the manifest (exit 1)'}])

    def test_hidden_reasons_are_fixed_sentences_never_copied_values(self):
        err = ('error: error parsing STDIN: error converting YAML to JSON: yaml: unmarshal errors:\n'
               '  line 4: cannot unmarshal !!str `hunter2` into map[string]interface {}\n'
               'error: Object \'Kind\' is missing in \'{"data":{"password":"hunter2"}}\'\n'
               'Error from server (Forbidden): secrets is forbidden: User "hunter2"\n'
               'unable to recognize "STDIN": no matches for kind "hunter2 and more" in version "v1"\n'
               'hunter2 is not an error line\n')
        out = self.shape(kubectl_out(CONFIGMAP_OBJ), rc=1, err=err)
        blob = json.dumps(out)
        self.assertNotIn('hunter2', blob)
        reasons = [h['reason'] for h in out['hidden']]
        self.assertIn('a document is not valid YAML', reasons)
        self.assertIn('a document has no apiVersion or kind', reasons)
        self.assertEqual(len(reasons), len(set(reasons)))
        self.assertLessEqual(len(reasons), inspect_ops.MAX_HIDDEN)
        many = '\n'.join('error: resource mapping not found: no matches for kind "K%d" in version "v1"' % i
                         for i in range(20))
        out = self.shape(kubectl_out(CONFIGMAP_OBJ), rc=1, err=many)
        self.assertEqual(len(out['hidden']), inspect_ops.MAX_HIDDEN)

    def test_cut_output_after_the_last_object_is_reported(self):
        out = self.shape(kubectl_out(CONFIGMAP_OBJ) + '{"apiVersion": "v1", "kind": "Secret", "data": {"k": "LE')
        self.assertEqual(out['objects'], [CONFIGMAP_OBJ])
        self.assertEqual(out['hidden'], [{'reason': 'the rest of the kubectl output could not be read'}])
        self.assertNotIn('LE', json.dumps(out['hidden']))

    def test_garbage_output_is_release_unparsable(self):
        for out, rc, err in (('this is not json', 0, ''), ('<html>nope</html>', 1, 'error: boom'),
                             ('', 0, ''), ('', 1, 'error: error parsing STDIN: yaml: line 2: did not find '
                                                  'expected node content\n'),
                             ('{"kind": ', 1, '')):
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.shape(out, rc=rc, err=err)
            self.assertEqual(cm.exception.code, 'release_unparsable', (out, rc))
            self.assertIn('could not be decoded', cm.exception.message)
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.shape('', rc=1, err='error: error parsing STDIN: cannot unmarshal !!str `hunter2`')
        self.assertNotIn('hunter2', cm.exception.message)
        self.assertEqual(inspect_ops.STATUS['release_unparsable'], 502)

    def test_a_manifest_without_objects_is_an_empty_release(self):
        out = self.shape('', rc=1, err='error: no objects passed to create\n')
        self.assertEqual((out['objects'], out['hidden']), ([], []))

    def test_an_api_server_that_does_not_answer_is_a_device_error(self):
        for err in ('unable to recognize "STDIN": Get "https://127.0.0.1:6443/api?timeout=15s": dial tcp '
                    '127.0.0.1:6443: connect: connection refused',
                    'error: ... context deadline exceeded'):
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.shape('', rc=1, err=err)
            self.assertEqual(cm.exception.code, 'device_error')

    def test_too_many_objects_and_too_complex_output_are_too_large(self):
        for n in (inspect_ops.RELEASE_MAX_OBJECTS + 1,):
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.shape(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [CONFIGMAP_OBJ] * n}))
            self.assertEqual(cm.exception.code, 'too_large')
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.shape(' '.join(['{"kind":"A"}'] * n))
            self.assertEqual(cm.exception.code, 'too_large')
        self.assertEqual(len(self.shape(json.dumps({'apiVersion': 'v1', 'kind': 'List',
                                                    'items': [CONFIGMAP_OBJ] * inspect_ops.RELEASE_MAX_OBJECTS}
                                                   ))['objects']), inspect_ops.RELEASE_MAX_OBJECTS)
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.shape('{"kind":"A","x":[' + '{},' * 250000 + '{}]}')
        self.assertEqual(cm.exception.code, 'too_large')

    def test_deeply_nested_output_never_crashes(self):
        # nested past what the parser may recurse into: too_large before json sees it (a segfault
        # on a small thread stack otherwise); nested past what is shown: the object is hidden
        for depth in (inspect_ops.JSON_MAX_DEPTH + 1, 1000, 150000):
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.on_small_stack(self.shape, '{"kind":"A","x":' + '[' * depth + ']' * depth + '}')
            self.assertEqual(cm.exception.code, 'too_large', depth)
        for depth, shown in ((inspect_ops.MAX_OBJECT_DEPTH - 3, True), (inspect_ops.MAX_OBJECT_DEPTH + 10, False),
                             (inspect_ops.JSON_MAX_DEPTH - 5, False)):
            deep = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'data': {}}
            node = deep['data']
            for _ in range(depth):
                node['k'] = {}
                node = node['k']
            out = self.on_small_stack(self.shape, json.dumps(deep) + json.dumps(CONFIGMAP_OBJ))
            self.assertEqual(len(out['objects']), 2 if shown else 1, depth)
            self.assertEqual(out['hidden'], [] if shown else [{'reason': 'an object nested too deep'}])
            json.dumps(out)

    def test_json_depth_check_ignores_brackets_in_strings(self):
        deep_text = json.dumps({'kind': 'A', 'x': '[' * 5000 + '{' * 5000, 'y': '\\"' + '[' * 5000})
        self.assertFalse(inspect_ops.json_too_deep(deep_text.encode()))
        self.assertTrue(inspect_ops.json_too_deep(b'[' * 201 + b']' * 201))
        self.assertFalse(inspect_ops.json_too_deep(b'[' * 200 + b']' * 200))
        self.assertEqual(self.shape(deep_text)['objects'][0]['kind'], 'A')

    def test_compact_json_over_the_manifest_cap_is_too_large(self):
        big = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'big'},
               'data': {'k': 'x' * (inspect_ops.MANIFEST_CAP + 1)}}
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.shape(json.dumps(big))
        self.assertEqual(cm.exception.code, 'too_large')
        big['data']['k'] = 'x' * (inspect_ops.MANIFEST_CAP - 1000)
        self.assertEqual(len(self.shape(json.dumps(big, indent=4))['objects']), 1)
        self.assertEqual(inspect_ops.KUBECTL_OUT_CAP, 2 * inspect_ops.MANIFEST_CAP)

    def test_an_object_in_another_namespace_is_present(self):
        # no `-n` on the command: kubectl keeps the namespace an object names (helm/k3s install such objects)
        other = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'kube-cfg', 'namespace': 'kube-system'}}
        unnamed = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'x', 'namespace': 'default'}}
        out = self.shape(kubectl_out(other, CONFIGMAP_OBJ, unnamed))
        self.assertEqual([(o['metadata']['name'], o['metadata']['namespace']) for o in out['objects']],
                         [('kube-cfg', 'kube-system'), ('nvr-config', 'teknoir-demo'), ('x', 'default')])
        self.assertEqual(out['hidden'], [])

    def test_unprefixed_resource_mapping_lines_give_one_reason_per_kind(self):
        err = ('resource mapping not found for name: "f1" namespace: "" from "STDIN": no matches for kind "Foo" '
               'in version "x/v1"\nensure CRDs are installed first\n'
               'resource mapping not found for name: "b1" namespace: "" from "STDIN": no matches for kind "Bar.baz" '
               'in version "y/v2"\nensure CRDs are installed first\n'
               'resource mapping not found for name: "f2" namespace: "" from "STDIN": no matches for kind "Foo" '
               'in version "x/v1"\nensure CRDs are installed first\n'
               'resource mapping not found for name: "w" namespace: "" from "STDIN": no matches for kind '
               '"Evil kind hunter2" in version "z/v1"\nensure CRDs are installed first\n')
        out = self.shape(KUBECTL_OK, rc=1, err=err)
        self.assertEqual(out['hidden'], [
            {'reason': 'an object of the unknown kind Foo (its CRD is not installed on the robot)'},
            {'reason': 'an object of the unknown kind Bar.baz (its CRD is not installed on the robot)'},
            {'reason': 'an object of an unknown kind (its CRD is not installed on the robot)'}])
        self.assertNotIn('hunter2', json.dumps(out))
        # with no object at all the reasons are in the error message, still fixed text
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.shape('', rc=1, err=err)
        self.assertIn('unknown kind Foo', cm.exception.message)
        self.assertNotIn('hunter2', cm.exception.message)

    def test_json_depth_scanner_is_linear_on_adversarial_strings(self):
        for raw in (b'"' + b'\\"' * (1 << 20),                 # 2 MiB: unterminated, every quote escaped
                    b'"' + b'\\' * (1 << 20) + b'"',           # backslash pairs, terminated
                    b'"",' * 700000, b'"a\\"b",' * 300000, b'[]' * (1 << 20), b'\\' * (2 << 20),
                    b'[' * 100 + b'"' + b'\\"' * (1 << 20)):
            started = time.monotonic()
            self.assertFalse(inspect_ops.json_too_deep(raw))
            self.assertLess(time.monotonic() - started, 0.5, raw[:12])
        started = time.monotonic()
        self.assertTrue(inspect_ops.json_too_deep(b'[' * 201 + b'"' + b'\\"' * (1 << 20)))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_json_depth_scanner_agrees_with_a_reference_state_machine(self):
        import random

        def reference(raw, limit):
            # Inside a string a backslash escapes the next byte. Outside a string a backslash is
            # invalid JSON (the parser stops there, so only text that is refused anyway differs);
            # the scanner reads a doubled backslash and a backslash-quote as a pair there too.
            depth, in_str, i = 0, False, 0
            while i < len(raw):
                c = raw[i]
                if c == 0x5c and (in_str or raw[i + 1:i + 2] in (b'\\', b'"')):
                    i += 2
                    continue
                if in_str:
                    if c == 0x22:
                        in_str = False
                elif c == 0x22:
                    in_str = True
                elif c in b'{[':
                    depth += 1
                    if depth > limit:
                        return True
                elif c in b'}]':
                    depth -= 1
                i += 1
            return False

        rnd = random.Random(7)
        alphabet = [b'"', b'\\', b'[', b']', b'{', b'}', b'a', b' ', b'\n']
        for _ in range(4000):
            raw = b''.join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
            for limit in (0, 1, 3):
                self.assertEqual(inspect_ops.json_too_deep(raw, limit), reference(raw, limit), (raw, limit))

    def test_the_budget_stops_the_shaping(self):
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.shape(KUBECTL_OK, budget=-1)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_no_yaml_is_parsed_here(self):
        # the manifest is Kubernetes' business; nothing in this module reads YAML
        self.assertFalse(hasattr(inspect_ops, 'yaml'))
        self.assertFalse(hasattr(inspect_ops, 'redact_manifest'))

    def test_manifest_argv_is_the_fixed_command(self):
        req = inspect_ops.parse_request({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr',
                                         'revision': 2})
        argv = inspect_ops.kubectl_manifest_argv(req)
        # no `-n`: it would make kubectl refuse every object that names another namespace
        self.assertEqual(argv, ['sudo', '-n', 'k3s', 'kubectl', '--request-timeout=15s',
                                'create', '--dry-run=client', '--validate=false', '-o', 'json', '-f', '-'])
        self.assertNotIn('-n', argv[4:])
        self.assertNotIn('teknoir-demo', argv)
        self.assertEqual(shlex.split(inspect_ops.remote_command(argv)), argv)

    def decode(self, data, rev=3, name='nvr', ns='teknoir-demo', **kw):
        return inspect_ops.decode_checked(data, name, ns, rev, **kw)

    def test_decode_drops_everything_else(self):
        for gz in (True, False):
            kept, manifest = self.decode(helm_release(MANIFEST, gz=gz))
            self.assertEqual(manifest, MANIFEST.encode())
            self.assertEqual(set(kept), {'name', 'namespace', 'version', 'status', 'last_deployed', 'chart',
                                         'chartVersion', 'appVersion'})          # no manifest text is kept
            out = inspect_ops.shape_release_objects(kept, [(3, 'deployed'), (2, 'superseded'), (1, 'superseded')],
                                                    'nvr', 'teknoir-demo', 3, 0, KUBECTL_OK.encode(), b'')
            self.assertEqual(set(out), {'name', 'namespace', 'revision', 'status', 'chart', 'chartVersion',
                                        'appVersion', 'lastDeployed', 'objects', 'hidden', 'history'})
            self.assertEqual(out['history'][0], {'revision': 3, 'status': 'deployed'})
            blob = json.dumps(out)
            for leaked in ('hunter2', 'chart-default-pw', 'SECRET NOTE', 'secret-hook', 'templates/x.yaml',
                           'aHVudGVyMg'):
                self.assertNotIn(leaked, blob)

    def test_the_manifest_is_decoded_byte_for_byte(self):
        odd = 'a: 1\r\n\ufeffb: \u0085c\u2028d\x00\U0001F600 \u00e5\n--- #x\n'
        _, manifest = self.decode(helm_release(odd))
        self.assertEqual(manifest, odd.encode('utf-8'))
        with self.assertRaises(inspect_ops.Failure) as cm:      # a lone surrogate has no UTF-8 form
            self.decode(helm_release('a: \ud800'))
        self.assertEqual(cm.exception.code, 'device_error')

    def test_history_capped_at_20(self):
        rows = [(i, 'superseded') for i in range(30, 0, -1)]
        out = inspect_ops.shape_release_objects(self.KEPT, rows, 'nvr', 'teknoir-demo', 3, 0, KUBECTL_OK.encode(), b'')
        self.assertEqual(len(out['history']), 20)

    def test_gzip_bomb_is_too_large(self):
        bomb = gzip.compress(b'{"manifest": "' + b'a' * (inspect_ops.RELEASE_JSON_CAP + 1000) + b'"}', 1)
        data = base64.b64encode(base64.b64encode(bomb)).decode()
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.decode_release(data)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_large_manifest_fails_fast_before_it_is_sent(self):
        # compressible and over the cap: refused when the record is decoded, nothing goes to the robot
        doc = '---\nkind: ConfigMap\ndata:\n  k: "%s"\n' % ('x' * 1000)
        manifest = doc * ((inspect_ops.MANIFEST_CAP // len(doc)) + 10)
        data = helm_release(manifest)
        self.assertLess(len(data), 200000)
        started = time.monotonic()
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.decode(data)
        self.assertEqual(cm.exception.code, 'too_large')
        self.assertLess(time.monotonic() - started, 2)

    @staticmethod
    def on_small_stack(fn, *args):
        """Run fn on a thread with a 1 MiB stack, like the worker thread on python:alpine (musl);
        a call that recurses in C then dies with SIGSEGV and takes the test run with it."""
        box = {}

        def run():
            try:
                box['value'] = fn(*args)
            except BaseException as exc:          # noqa
                box['error'] = exc
        old = threading.stack_size(1 << 20)
        try:
            t = threading.Thread(target=run)
            t.start()
        finally:
            threading.stack_size(old)
        t.join()
        if 'error' in box:
            raise box['error']
        return box['value']

    # -- JSON value bound, UTF-8 decoding, metadata cap

    def record(self, body):
        """A decode_release input: `body` (bytes, up to 8 MiB) gzipped and base64 twice."""
        return base64.b64encode(base64.b64encode(gzip.compress(body))).decode()

    def measured(self, fn):
        """(result or Failure code, seconds, tracemalloc peak bytes above the start) of fn()."""
        tracemalloc.start()
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        started = time.monotonic()
        try:
            try:
                out = fn()
            except inspect_ops.Failure as f:
                out = f.code
            peak = tracemalloc.get_traced_memory()[1] - base
        finally:
            tracemalloc.stop()
        return out, time.monotonic() - started, peak

    def adversarial_8mib(self):
        size = inspect_ops.RELEASE_JSON_CAP
        def fit(head, unit, tail):
            return head + unit * ((size - len(head) - len(tail)) // len(unit)) + tail
        pieces = {
            'short strings': fit(b'[', b'"a",', b'"a"]'),
            'short strings spaced': fit(b'[', b'"a" ,', b'"a"]'),
            'floats': fit(b'[', b'1.5,', b'1.5]'),
            'ints': fit(b'[', b'1,', b'1]'),
            'keys': fit(b'{', b'"k":1,', b'"k":1}'),
            'close brackets': b'}' * size,
            'empty objects': fit(b'[', b'{},', b'{}]'),
        }
        for name, body in pieces.items():
            self.assertLessEqual(len(body), size, name)
            self.assertGreater(len(body), size - 64, name)
        return pieces

    def test_release_value_count_is_bounded_at_the_real_input_size(self):
        for name, body in self.adversarial_8mib().items():
            out, secs, peak = self.measured(lambda: inspect_ops.decode_release(self.record(body)))
            self.assertEqual(out, 'too_large', name)
            self.assertLess(secs, 3.0, name)
            self.assertLess(peak, 64 * 1024 * 1024, (name, peak))

    def test_scanner_alone_is_quick_and_bounded_at_8mib(self):
        for name, body in self.adversarial_8mib().items():
            out, secs, peak = self.measured(lambda: inspect_ops.json_scan(body, inspect_ops.RELEASE_JSON_VALUES))
            self.assertEqual(out, 'values', name)
            self.assertLess(secs, 1.0, name)
            self.assertLess(peak, 64 * 1024 * 1024, (name, peak))

    def test_kubectl_stream_value_count_is_bounded_at_the_real_input_size(self):
        for name, body in self.adversarial_8mib().items():
            body = body[:inspect_ops.KUBECTL_OUT_CAP]
            out, secs, peak = self.measured(lambda: inspect_ops.parse_object_stream(body))
            self.assertEqual(out, 'too_large', name)
            self.assertLess(secs, 1.0, name)
            self.assertLess(peak, 64 * 1024 * 1024, (name, peak))

    def test_value_count_counts_the_values_outside_strings_only(self):
        big_string = b'{"a":"' + b',:[]{}' * 100000 + b'"}'          # 3 values and 1 big string
        self.assertIsNone(inspect_ops.json_scan(big_string, 3))
        self.assertEqual(inspect_ops.json_scan(big_string, 2), 'values')
        self.assertIsNone(inspect_ops.json_scan(b'[1,2,3]', 7))     # 2 brackets and 2 commas ... plus
        self.assertEqual(inspect_ops.json_scan(b'[1,2,3]', 3), 'values')
        # a realistic record is far under the limit
        self.assertEqual(inspect_ops.decode_release(helm_release(MANIFEST))['name'], 'nvr')

    def test_scanner_agrees_with_a_reference_and_with_tiny_chunks(self):
        import random

        def reference(raw):
            values, depth, deepest, in_str, i = 0, 0, 0, False, 0
            while i < len(raw):
                c = raw[i]
                if c == 0x5c and (in_str or raw[i + 1:i + 2] in (b'\\', b'"')):
                    i += 2
                    continue
                if in_str:
                    in_str = c != 0x22
                elif c == 0x22:
                    in_str = True
                elif c in b',:':
                    values += 1
                elif c in b'{[':
                    values += 1
                    depth += 1
                    deepest = max(deepest, depth)
                elif c in b'}]':
                    values += 1
                    depth -= 1
                i += 1
            return values, deepest

        rnd = random.Random(11)
        alphabet = [b'"', b'\\', b'[', b']', b'{', b'}', b',', b':', b'a', b' ']
        saved = inspect_ops._SCAN_CHUNK
        try:
            for chunk in (1, 2, 3, 7, saved):
                inspect_ops._SCAN_CHUNK = chunk
                for _ in range(1500):
                    raw = b''.join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
                    values, deepest = reference(raw)
                    self.assertEqual(inspect_ops.json_scan(raw, values) == 'values', False, (chunk, raw))
                    if values:
                        self.assertEqual(inspect_ops.json_scan(raw, values - 1) == 'values', True, (chunk, raw))
                    self.assertEqual(inspect_ops.json_too_deep(raw, deepest), False, (chunk, raw))
                    if deepest:
                        self.assertEqual(inspect_ops.json_too_deep(raw, deepest - 1), True, (chunk, raw))
        finally:
            inspect_ops._SCAN_CHUNK = saved

    def test_utf16_record_cannot_skip_the_depth_check(self):
        deep = '{"name":"nvr","namespace":"teknoir-demo","version":3,"manifest":"","x":%s%s}' % (
            '[' * 5000, ']' * 5000)
        # a lone U+0122 is the bytes 22 01: the byte scan reads a quote and takes the brackets after
        # it for the inside of a string, while a UTF-16 sniffing json.loads would read them as brackets
        skew = '["\u0122",' + '[' * 5000 + ']' * 5000 + ']'
        calls = []
        real_loads = inspect_ops.json.loads

        def spy(doc, *a, **k):
            calls.append(type(doc))
            return real_loads(doc, *a, **k)
        inspect_ops.json.loads = spy
        try:
            for text in (deep, skew):
                for codec in ('utf-16-le', 'utf-16', 'utf-16-be', 'utf-32-le'):
                    data = self.record(text.encode(codec))
                    with self.assertRaises(inspect_ops.Failure) as cm:
                        inspect_ops.decode_release(data)
                    self.assertIn(cm.exception.code, ('device_error', 'too_large'), codec)
                    if text is skew:
                        self.assertEqual(cm.exception.code, 'device_error', codec)
        finally:
            inspect_ops.json.loads = real_loads
        self.assertNotIn(bytes, calls)
        # the same text as UTF-8 is refused for its depth
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.decode_release(self.record(deep.encode()))
        self.assertEqual(cm.exception.code, 'too_large')
        # device output (pod, events) is decoded the same way
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops._json(skew.encode('utf-16-le'))
        self.assertEqual(cm.exception.code, 'device_error')
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops._json(b'[' * 5000 + b']' * 5000)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_release_metadata_strings_are_capped(self):
        long = 'x' * 5000
        rel = {'name': 'nvr', 'namespace': 'teknoir-demo', 'version': 3, 'manifest': 'm',
               'info': {'status': long, 'last_deployed': long},
               'chart': {'metadata': {'name': long, 'version': long, 'appVersion': long}}}
        kept = inspect_ops.decode_release(self.record(json.dumps(rel).encode()))
        for key in ('status', 'last_deployed', 'chart', 'chartVersion', 'appVersion'):
            self.assertEqual(kept[key], 'x' * inspect_ops.RELEASE_META_CAP, key)
        self.assertEqual(inspect_ops.RELEASE_META_CAP, 256)
        self.assertEqual((kept['name'], kept['manifest']), ('nvr', 'm'))
        # not strings: None, as in the backend (a number, a mapping or a huge list is never passed on)
        rel['info'] = {'status': 7, 'last_deployed': None}
        kept = inspect_ops.decode_release(self.record(json.dumps(rel).encode()))
        self.assertEqual((kept['status'], kept['last_deployed']), (None, None))

    def test_release_metadata_that_is_not_a_string_is_none(self):
        huge = ['x' * 1000] * 2000                                          # a 2 MB list in `status`
        rel = {'name': 'nvr', 'namespace': 'teknoir-demo', 'version': 3, 'manifest': 'm',
               'info': {'status': huge, 'last_deployed': {'a': huge}},
               'chart': {'metadata': {'name': 5, 'version': True, 'appVersion': [1]}}}
        kept = inspect_ops.decode_release(self.record(json.dumps(rel).encode()))
        for key in ('status', 'last_deployed', 'chart', 'chartVersion', 'appVersion'):
            self.assertIsNone(kept[key], key)
        out = inspect_ops.shape_release_objects(kept, [(3, 'deployed')], 'nvr', 'teknoir-demo', 3, 0,
                                                kubectl_out(CONFIGMAP_OBJ).encode(), b'')
        self.assertIsNone(out['status'])
        self.assertIsNone(out['chart'])
        self.assertNotIn('appVersion', out)
        self.assertNotIn('lastDeployed', out)
        self.assertLess(len(json.dumps(out)), 2000)

    def test_manifest_failure_names_nothing_from_stderr(self):
        secret = 'hunter2'
        for rc, err in ((255, 'error: cannot unmarshal !!str %s into Go value' % secret),
                        (255, 'ssh: connect to host x port 22: Connection refused %s' % secret),
                        (255, '')):
            f = inspect_ops.manifest_failure(err.encode(), rc)
            self.assertEqual((f.code, f.message), ('unavailable', 'The ssh session to the robot ended.'))
        f = inspect_ops.manifest_failure(b'access denied: device_offline (last seen 5m ago)', 255)
        self.assertEqual(f.code, 'offline')
        f = inspect_ops.manifest_failure(b'sudo: a password is required', 1)
        self.assertEqual(f.code, 'device_error')
        f = inspect_ops.manifest_failure(b'sudo: a password is required', 255)
        self.assertEqual(f.code, 'device_error')

    def test_release_json_nested_too_deep_is_a_contract_error(self):
        rel = '{"name":"nvr","namespace":"teknoir-demo","version":3,"manifest":"","x":%s%s}' % (
            '[' * 300000, ']' * 300000)
        data = base64.b64encode(base64.b64encode(gzip.compress(rel.encode()))).decode()
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.decode_release(data)
        self.assertIn(cm.exception.code, ('too_large', 'device_error'))

    def test_device_json_nested_too_deep_is_a_contract_error(self):
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops._json('[' * 300000 + ']' * 300000)
        self.assertIn(cm.exception.code, ('too_large', 'device_error'))

    def test_budget_stops_the_decoding(self):
        with self.assertRaises(inspect_ops.Failure) as cm:
            self.decode(helm_release(MANIFEST), budget=-1)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_release_must_match_the_request(self):
        ok, _ = self.decode(helm_release(MANIFEST))
        self.assertIs(type(ok['version']), int)
        for name, ns, rev in (('other', 'teknoir-demo', 3), ('nvr', 'elsewhere', 3), ('nvr', 'teknoir-demo', 2)):
            with self.assertRaises(inspect_ops.Failure) as cm:
                self.decode(helm_release(MANIFEST), rev=rev, name=name, ns=ns)
            self.assertEqual(cm.exception.code, 'device_error', (name, ns, rev))
        for version in (None, '3', 3.0, True):
            data = helm_release(MANIFEST, version=version)
            for rev in (3, 1):
                with self.assertRaises(inspect_ops.Failure) as cm:
                    self.decode(data, rev=rev)
                self.assertEqual(cm.exception.code, 'device_error', version)

    def test_object_dense_release_json_is_too_large(self):
        # 8 MiB of `{}` would need ~250 MiB inside json.loads; refused before it is built
        rel = '{"name":"nvr","namespace":"teknoir-demo","version":3,"manifest":"","x":[%s]}' % ','.join(
            ['{}'] * 2000000)
        self.assertLess(len(rel), inspect_ops.RELEASE_JSON_CAP)
        data = base64.b64encode(base64.b64encode(gzip.compress(rel.encode()))).decode()
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.decode_release(data)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_manifest_cap_matches_the_backend(self):
        self.assertEqual(inspect_ops.MANIFEST_CAP, 2 * 1024 * 1024)     # RELEASE_MAX_MANIFEST_BYTES

    def test_release_json_cap_is_8_mib(self):
        self.assertEqual(inspect_ops.RELEASE_JSON_CAP, 8 * 1024 * 1024)

    def test_bad_encodings(self):
        for data in ('!!!notbase64', base64.b64encode(b'###').decode(),
                     base64.b64encode(base64.b64encode(b'not json')).decode(),
                     base64.b64encode(base64.b64encode(b'\x1f\x8b\x08garbage')).decode(),
                     base64.b64encode(base64.b64encode(b'[1,2]')).decode()):
            with self.assertRaises(inspect_ops.Failure) as cm:
                inspect_ops.decode_release(data)
            self.assertEqual(cm.exception.code, 'device_error', data)

    def test_pick_revision(self):
        rows = inspect_ops.parse_release_list(b'1\tsuperseded\n3\tfailed\n2\tdeployed\ngarbage\n\n4\n')
        self.assertEqual(rows, [(3, 'failed'), (2, 'deployed'), (1, 'superseded')])
        self.assertEqual(inspect_ops.pick_revision(rows, None), 2)           # newest deployed
        self.assertEqual(inspect_ops.pick_revision(rows, 3), 3)
        self.assertIsNone(inspect_ops.pick_revision(rows, 9))
        self.assertEqual(inspect_ops.pick_revision([(5, 'failed'), (4, 'failed')], None), 5)   # else newest


@unittest.skipUnless(sys.platform.startswith('linux'), 'VmHWM is read from /proc/self/status')
class TestPeakMemory(unittest.TestCase):
    """Process peak (VmHWM of /proc/self/status) of the shaping jobs, one FRESH process per case (the
    peak of a process never goes down, so cases cannot share one). Not ru_maxrss: that mark is
    inherited across fork+exec, so in the full suite (a big parent process) it hid every regression;
    the probe also reports its own baseline and the test asserts it is a small fresh interpreter.
    Every string in every input holds one
    non-BMP character: CPython then stores it at 4 bytes per character, and the decoded text, the
    parsed values and the bytes are alive together. Every input passes the value and depth scan,
    so the memory is spent before any size verdict. Peaks are MiB above the process right after
    its imports (the input held in memory included); measured on Python 3.11 / Linux before and
    after the change (tests/rss_probe.py):

      case            before   after (limit)
      shape_single     111.8   39.8 (56)       kubectl stdout at its cap, one big string
      shape_long       105.3   36.2 (56)       8300 / 4100 strings of 1000 characters
      shape_many       125.7   38.8 (56)       50000 strings of 150 characters
      shape_objects    100.4   33.2 (56)       1500 objects
      shape_ok          24.4   16.5 (40)       the largest accepted answer (about 2 MiB compact)
      decode_single     79.8   72.1 (100)      8 MiB record, one big string
      decode_long       70.7   62.3 (100)
      decode_many       89.2   81.0 (100)      8 MiB record, 80000 small objects
      decode_values     40.5   15.8 (24)       refused on the value count before the text is built
      events            18.0   18.0 (40)
      release_op        20.4   19.3 (28)       a whole release op with a 1.5 MiB manifest and one astral
                                              character (see below for what it still holds)

    release_op also measures what the op still references (tracemalloc) when the manifest goes to the
    robot and when the shaping job starts: before 11.3 / 11.3 MiB (the record text, the secret and
    the manifest as a 6 MiB str), after 1.5 (the manifest bytes being written) / 0.0.
    The cap of kubectl's stdout went from 8 MiB to 4 MiB (shape_*: the 8 MiB input needs 69-80 MiB
    even with the new code); RELEASE_JSON_CAP stays 8 MiB (decode_*: about 40 MiB of text plus
    values at the cap, in one job at a time)."""

    LIMITS = {'shape_single': 56, 'shape_long': 56, 'shape_many': 56, 'shape_objects': 56,
              'shape_ok': 40, 'decode_single': 100, 'decode_long': 100, 'decode_many': 100,
              'decode_values': 24, 'events': 40, 'release_op': 28}
    BASELINE_LIMIT = 40          # a fresh interpreter with the imports is about 30 MiB
    HELD_AT_MANIFEST_CALL = 3    # MiB; the manifest bytes (1.5) are what the call writes
    HELD_AT_SHAPING = 1

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.probed = {}
        cls.probe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rss_probe.py')
        cls.app = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'app')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def probe_case(self, case):
        import rss_probe
        path = os.path.join(self.tmp, case + '.bin')
        for mode in ('gen', 'run'):
            proc = subprocess.run([sys.executable, '-I', self.probe, mode, self.app, case, path],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        result = json.loads(proc.stdout)
        self.assertEqual(result['outcome'], rss_probe.CASES[case], case)
        # a mark inherited from a big parent would show here, not as a quiet pass
        self.assertLess(result['baseline_mib'], self.BASELINE_LIMIT, (case, result))
        self.probed[case] = result
        return result['peak_mib']

    def test_the_cases_and_limits_agree(self):
        import rss_probe
        self.assertEqual(sorted(rss_probe.CASES), sorted(self.LIMITS))

    def test_peak_memory_of_shaping_kubectl_output_and_release_records(self):
        peaks = {case: self.probe_case(case) for case in sorted(self.LIMITS)}
        for case, peak in peaks.items():
            self.assertLess(peak, self.LIMITS[case], (case, peaks))

    def test_a_release_op_drops_the_record_and_the_manifest_text(self):
        """End to end (list, secret, manifest, shaping), a manifest with one astral character (a str of
        4 bytes per character): the secret, its text and the manifest str are not referenced while the
        manifest goes to the robot and while the shaping job runs."""
        peak = self.probe_case('release_op')
        result = self.probed['release_op']
        self.assertLess(peak, self.LIMITS['release_op'], result)
        self.assertLess(result['held_at_manifest_call_mib'], self.HELD_AT_MANIFEST_CALL, result)
        self.assertLess(result['held_at_shaping_mib'], self.HELD_AT_SHAPING, result)

    def test_decode_checked_keeps_no_manifest_text(self):
        kept, manifest = inspect_ops.decode_checked(helm_release(MANIFEST), 'nvr', 'teknoir-demo', 3)
        self.assertNotIn('manifest', kept)
        self.assertEqual(manifest, MANIFEST.encode())

    def test_kubectl_stdout_cap_is_4_mib(self):
        self.assertEqual(inspect_ops.KUBECTL_OUT_CAP, 4 * 1024 * 1024)


class TestPrincipalsAndXfcc(unittest.TestCase):
    def test_parse_principals(self):
        self.assertEqual(inspect_ops.parse_principals(None), [])
        self.assertEqual(inspect_ops.parse_principals(''), [])
        self.assertEqual(inspect_ops.parse_principals(' , '), [])
        self.assertEqual(inspect_ops.parse_principals(PRINCIPAL + ', cluster.local/ns/a/sa/b'),
                         [PRINCIPAL, 'cluster.local/ns/a/sa/b'])
        self.assertEqual(inspect_ops.parse_principals('spiffe://x/ns/a/sa/b,cluster.local/ns/A/sa/b'), [])

    def test_xfcc_single_element(self):
        uris = inspect_ops.xfcc_uris(['By=z;Hash=abc;Subject="CN=a,O=b";URI=spiffe://' + PRINCIPAL])
        self.assertEqual(uris, ['spiffe://' + PRINCIPAL])
        uris = inspect_ops.xfcc_uris(['Subject="CN=a,O=b;URI=spiffe://fake";URI=spiffe://real'])
        self.assertEqual(uris, ['spiffe://real'])
        self.assertEqual(inspect_ops.xfcc_uris([]), [])

    def test_xfcc_fails_closed_on_forged_or_malformed(self):
        envoy = ('By=spiffe://cluster.local/ns/teknoir-system/sa/wgt-abc;Hash=deadbeef;Subject="";'
                 'URI=spiffe://cluster.local/ns/teknoir-demo/sa/attacker')
        forged = 'URI=spiffe://' + PRINCIPAL
        cases = [
            # the reported bypass: an unclosed quote swallows the real URI of Envoy's element
            [forged + ';x="', envoy],
            [forged + ';x="' + ',' + envoy],
            # a forged element before Envoy's, balanced or not
            [forged, envoy],
            [forged + ',' + envoy],
            [forged + ';x="a"', envoy],
            [envoy, forged],
            # unbalanced or dangling-escape quotes alone
            ['URI=spiffe://' + PRINCIPAL + ';x="'],
            ['Subject="abc\\'],
            # more than one element
            ['URI=spiffe://' + PRINCIPAL + ',URI=spiffe://evil/ns/x/sa/y'],
            ['URI=spiffe://evil/ns/x/sa/y,By=z;URI=spiffe://' + PRINCIPAL],
        ]
        for values in cases:
            self.assertEqual(inspect_ops.xfcc_uris(values), [], values)


class InspectHTTPBase(FakeSSHMixin, AsyncHTTPTestCase):
    runner_kwargs = {}

    def get_app(self):
        self.setup_fake()
        self.app = inspect_ops.make_inspect_app(make_config(), [PRINCIPAL], ssh=self.ssh,
                                                base_dir=self.base_dir, **self.runner_kwargs)
        return self.app

    def tearDown(self):
        self.io_loop.run_sync(self.app.settings['inspect_runner'].close)
        super().tearDown()

    def post(self, body, user=ALICE, xfcc=XFCC_OK, ctype='application/json', raw=None, headers=None):
        h = {'Content-Type': ctype}
        if user is not None:
            h['X-Inspect-User'] = user
        if xfcc is not None:
            h['X-Forwarded-Client-Cert'] = xfcc
        h.update(headers or {})
        data = raw if raw is not None else json.dumps(body)
        return self.fetch('/inspect/v1/op', method='POST', body=data, headers=h, follow_redirects=False)

    def body_of(self, resp):
        self.assertEqual(resp.headers['Content-Type'], 'application/json')
        self.assertEqual(resp.headers['Cache-Control'], 'no-store')
        return json.loads(resp.body)

    def err(self, resp, status, code):
        self.assertEqual(resp.code, status, resp.body)
        data = self.body_of(resp)
        self.assertEqual(data['error']['code'], code)
        self.assertEqual(data['v'], 1)
        return data['error']

    POD = {'v': 1, 'op': 'pod', 'namespace': 'teknoir-demo', 'pod': 'nvr-1'}


class TestEndpoint(InspectHTTPBase):
    def test_health_needs_no_ssh(self):
        resp = self.fetch('/inspect/v1/healthz')
        self.assertEqual(self.body_of(resp), {'ok': True})
        self.assertEqual(self.calls(), [])

    def test_methods_and_paths(self):
        self.assertEqual(self.fetch('/inspect/v1/op').code, 405)
        self.assertEqual(self.fetch('/inspect/v1/op', method='PUT', body='{}').code, 405)
        self.assertEqual(self.fetch('/inspect/v1/healthz', method='POST', body='{}').code, 405)
        resp = self.fetch('/inspect/v1/other')
        self.assertEqual(resp.code, 404)
        self.assertEqual(self.body_of(resp)['error']['code'], 'not_found')
        self.assertEqual(self.fetch('/').code, 404)
        self.assertNotIn('Access-Control-Allow-Origin', self.fetch('/inspect/v1/healthz').headers)

    def test_peer_check(self):
        for xfcc in (None, '', 'URI=spiffe://cluster.local/ns/teknoir-demo/sa/other',
                     'URI=spiffe://' + PRINCIPAL + ',URI=spiffe://cluster.local/ns/x/sa/y',
                     'URI=' + PRINCIPAL, 'URI=spiffe://' + PRINCIPAL + 'x',
                     'URI=spiffe://' + PRINCIPAL + ';x="',
                     'URI=spiffe://' + PRINCIPAL + ';x=",' + XFCC_OK):
            self.err(self.post(self.POD, xfcc=xfcc), 403, 'forbidden')
        self.assertEqual(self.calls(), [])

    def test_peer_check_comes_before_user_check(self):
        self.err(self.post(self.POD, user=None, xfcc=None), 403, 'forbidden')

    def test_user_header(self):
        for user in (None, '', 'not-an-email', 'a b@example.com', 'x@y.z; reboot', '$(id)@example.com'):
            self.err(self.post(self.POD, user=user), 401, 'no_user')
        # the oauth2-proxy header is ignored on this port
        self.err(self.post(self.POD, user=None, headers={'X-Auth-Request-Email': ALICE}), 401, 'no_user')
        self.assertEqual(self.calls(), [])

    def test_body_rules(self):
        self.err(self.post(None, ctype='text/plain', raw=json.dumps(self.POD)), 400, 'invalid')
        self.err(self.post(None, ctype='application/x-www-form-urlencoded', raw='op=pod'), 400, 'invalid')
        self.err(self.post(None, raw='{not json'), 400, 'invalid')
        self.err(self.post(None, raw='{"v":1,"op":"pod","namespace":"n","pod":NaN}'), 400, 'invalid')
        self.err(self.post(None, raw=b'\xff\xfe'.decode('latin-1')), 400, 'invalid')
        self.err(self.post(None, raw='[]'), 400, 'invalid')
        big = dict(self.POD, pod='a' * 5000)
        self.err(self.post(big), 400, 'invalid')
        padded = json.dumps(self.POD) + ' ' * 5000
        self.err(self.post(None, raw=padded), 400, 'invalid')
        self.err(self.post(dict(self.POD, extra=1)), 400, 'invalid')
        self.err(self.post(dict(self.POD, pod='-n')), 400, 'invalid')
        self.assertEqual(self.calls(), [])
        # a charset parameter on the content type is fine
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{"name":"nvr-1"}}'}]})
        self.assertEqual(self.post(self.POD, ctype='application/json; charset=utf-8').code, 200)

    def test_pod_end_to_end(self):
        self.scenario({'ops': [{'match': 'get pod nvr-1', 'stdout': json.dumps(
            {'metadata': {'name': 'nvr-1', 'annotations': {'x': 'y'}},
             'spec': {'containers': [{'name': 'c', 'env': [{'name': 'TOKEN', 'value': 'abc'}]}]}})}]})
        resp = self.post(self.POD, headers={'X-Request-Id': 'req-1.a'})
        self.assertEqual(resp.code, 200)
        data = self.body_of(resp)
        self.assertEqual((data['v'], data['op']), (1, 'pod'))
        self.assertIsInstance(data['ms'], int)
        self.assertEqual(data['result']['pod']['metadata'], {'name': 'nvr-1'})
        self.assertEqual(data['result']['pod']['spec']['containers'][0]['env'][0]['value'], '<hidden>')

    def test_pod_and_events_are_parsed_off_the_event_loop(self):
        threads = []
        orig_pod, orig_events = inspect_ops.prune_pod, inspect_ops.shape_events

        def pod(doc):
            threads.append(threading.current_thread())
            return orig_pod(doc)

        def events(doc, *a, **k):
            threads.append(threading.current_thread())
            return orig_events(doc, *a, **k)
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{"name":"nvr-1"}}'},
                               {'match': 'get events', 'stdout': '{"items":[]}'}]})
        inspect_ops.prune_pod, inspect_ops.shape_events = pod, events
        try:
            self.assertEqual(self.post(self.POD).code, 200)
            self.assertEqual(self.post(dict(self.POD, op='events')).code, 200)
        finally:
            inspect_ops.prune_pod, inspect_ops.shape_events = orig_pod, orig_events
        self.assertEqual(len(threads), 2)
        for t in threads:
            self.assertIsNot(t, threading.main_thread())
            self.assertTrue(t.name.startswith('inspect'), t.name)

    def test_pod_and_events_json_with_too_many_objects_is_too_large(self):
        # under the byte caps, but ~100 MiB once json.loads has built it: refused before parsing
        pod = '[' + ','.join(['{}'] * (inspect_ops.POD_JSON_VALUES // 3 + 10)) + ']'
        events = '[' + ','.join(['{}'] * (inspect_ops.EVENTS_JSON_VALUES // 3 + 10)) + ']'
        self.assertLess(len(pod), inspect_ops.POD_CAP)
        self.assertLess(len(events), inspect_ops.EVENTS_CAP)
        self.scenario({'ops': [{'match': 'get pod', 'stdout': pod}, {'match': 'get events', 'stdout': events}]})
        self.err(self.post(self.POD), 413, 'too_large')
        self.err(self.post(dict(self.POD, op='events')), 413, 'too_large')
        runner = self.app.settings['inspect_runner']
        self.assertEqual(runner._light_jobs, 0)

    def test_pod_and_events_jobs_are_bounded_and_counted(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{"name":"nvr-1"}}'}]})
        runner = self.app.settings['inspect_runner']
        runner._light_jobs = inspect_ops.MAX_LIGHT_JOBS
        self.assertEqual(self.err(self.post(self.POD), 429, 'busy')['retryAfter'], 5)
        runner._light_jobs = 0
        self.assertEqual(self.post(self.POD).code, 200)
        self.assertEqual(runner._light_jobs, 0)

    def _blocked_pool(self, runner):
        release, started = threading.Event(), threading.Event()

        def block():
            started.set()
            release.wait(20)
        runner.pool.submit(block)
        self.assertTrue(started.wait(5))
        self.addCleanup(release.set)
        return release

    @staticmethod
    def _release_job(runner):
        return runner._run_job(runner.pool, '_jobs', inspect_ops.MAX_RELEASE_JOBS,
                               lambda: inspect_ops.decode_checked('x', 'nvr', 'teknoir-demo', 3))

    def test_job_slots_of_cancelled_queued_jobs_are_given_back(self):
        # The op's 20 s wait_for cancels a job that is still queued behind a running one. Such a job
        # never runs, so only the submitted future can give its slot back.
        runner = self.app.settings['inspect_runner']
        self._blocked_pool(runner)

        async def go():
            seen = []
            for _ in range(inspect_ops.MAX_RELEASE_JOBS + 3):
                with self.assertRaises(asyncio.TimeoutError):     # busy would be a Failure instead
                    await asyncio.wait_for(self._release_job(runner), 0.05)
                seen.append(runner._jobs)
            return seen
        self.assertEqual(self.io_loop.run_sync(go), [0] * (inspect_ops.MAX_RELEASE_JOBS + 3))

    def test_job_slot_of_a_running_job_is_held_until_it_ends(self):
        runner = self.app.settings['inspect_runner']
        release, started = threading.Event(), threading.Event()
        orig = inspect_ops.decode_checked

        def slow(*a, **k):
            started.set()
            release.wait(20)
            return {'ok': True}
        inspect_ops.decode_checked = slow
        self.addCleanup(setattr, inspect_ops, 'decode_checked', orig)
        self.addCleanup(release.set)

        async def go():
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(self._release_job(runner), 0.3)
            return started.is_set(), runner._jobs
        self.assertEqual(self.io_loop.run_sync(go), (True, 1))     # cancelled but still running
        release.set()
        for _ in range(100):
            if runner._jobs == 0:
                break
            time.sleep(0.05)
        self.assertEqual(runner._jobs, 0)

    def test_events_end_to_end_keeps_the_newest_200(self):
        items = [{'reason': 'r%d' % i, 'lastTimestamp': '2026-10-22T%02d:%02d:00Z' % (i // 60, i % 60)}
                 for i in range(500)]
        self.scenario({'ops': [{'match': 'get events', 'stdout': json.dumps({'items': items})}]})
        result = self.body_of(self.post(dict(self.POD, op='events')))['result']
        self.assertTrue(result['truncated'])
        self.assertEqual([e['reason'] for e in result['events']][:2], ['r300', 'r301'])
        self.assertEqual(len(result['events']), 200)

    def test_log_line_has_no_content(self):
        self.scenario({'ops': [{'match': 'logs', 'stdout': 'SUPERSECRETLINE\n'}]})
        with self.assertLogs('inspect_ops', level='INFO') as cm:
            resp = self.post(dict(self.POD, op='logs'), headers={'X-Request-Id': 'rq-9'})
        self.assertEqual(resp.code, 200)
        line = '\n'.join(cm.output)
        self.assertIn('inspect op=logs user=alice@example.com ns=teknoir-demo target=teknoir-demo/nvr-1 '
                      'result=ok ms=', line)
        self.assertIn('bytes=16 reqId=rq-9', line)
        self.assertNotIn('SUPERSECRETLINE', line)
        with self.assertLogs('inspect_ops', level='INFO') as cm:
            self.post(dict(self.POD, pod='-n'), headers={'X-Request-Id': 'bad id!'})
        self.assertIn('result=invalid', cm.output[0])
        self.assertIn('reqId=-', cm.output[0])

    def test_events_logs_release_end_to_end(self):
        events = {'items': [{'type': 'Warning', 'reason': 'BackOff', 'lastTimestamp': '2026-10-22T10:00:00Z'}]}
        rel = helm_release(MANIFEST)
        self.scenario({'ops': [
            {'match': 'get events', 'stdout': json.dumps(events)},
            {'match': 'logs nvr-1', 'stdout': '2026-10-22T10:00:00Z hello\n',
             'stderr': 'Defaulted container "nvr" out of: nvr, side\n'},
            {'match': 'get secrets -l', 'stdout': '2\tsuperseded\n3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': rel},
            {'match': CREATE, 'stdout': KUBECTL_OK},
        ]})
        data = self.body_of(self.post(dict(self.POD, op='events')))
        self.assertEqual(data['result']['events'][0]['reason'], 'BackOff')
        data = self.body_of(self.post(dict(self.POD, op='logs', tail=10)))
        self.assertEqual(data['result']['container'], 'nvr')
        self.assertEqual(data['result']['lines'], 1)
        data = self.body_of(self.post({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}))
        self.assertEqual(data['result']['revision'], 3)
        self.assertNotIn('manifest', data['result'])
        self.assertEqual(len(data['result']['objects']), 2)
        self.assertNotIn('hunter2', json.dumps(data))
        self.assertNotIn('aHVudGVyMg', json.dumps(data))

    def test_release_explicit_revision_and_missing(self):
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '1\tsuperseded\n2\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v1', 'stdout': helm_release(MANIFEST, version=1, status='superseded', namespace='n')},
            {'match': CREATE, 'stdout': KUBECTL_OK},
        ]})
        body = {'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr', 'revision': 1}
        self.assertEqual(self.body_of(self.post(body))['result']['revision'], 1)
        self.err(self.post(dict(body, revision=7)), 404, 'not_found')
        self.scenario({'ops': [{'match': 'get secrets -l', 'stdout': ''}]})
        self.err(self.post(dict(body, revision=1)), 404, 'not_found')
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr'}), 404, 'not_found')

    REL = {'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}
    K = 'sudo -n k3s kubectl --request-timeout=15s'

    def release_scenario(self, create, manifest=MANIFEST):
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': helm_release(manifest)},
            dict({'match': CREATE}, **create),
        ]})

    def create_calls(self):
        return [c for c in self.op_calls() if CREATE in c['argv'][-1]]

    def test_release_manifest_goes_to_the_fixed_command_on_stdin_byte_for_byte(self):
        odd = MANIFEST + 'x: "a\r\nb \u00e5 \U0001F600 \u2028 \ufeff"\r\n--- #c\r\n# $(touch /tmp/x) `id` ; \'"\n'
        self.release_scenario({'stdout': KUBECTL_OK}, odd)
        data = self.body_of(self.post(self.REL))
        calls = self.create_calls()
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(base64.b64decode(call['stdin_b64']), odd.encode('utf-8'))
        # the remote command is exactly the fixed one: the manifest is in no argument, nowhere
        self.assertEqual(call['argv'][-1], self.K + ' create --dry-run=client --validate=false -o json -f -')
        self.assertEqual(call['argv'][-2], '--')
        for arg in call['argv']:
            self.assertNotIn('touch', arg)
            self.assertNotIn('Source: nvr', arg)
        # the other ops of the release never get a stdin
        for c in self.op_calls():
            if CREATE not in c['argv'][-1]:
                self.assertNotIn('stdin_b64', c)
        self.assertEqual(data['result']['revision'], 3)

    def test_release_result_is_the_object_list_without_a_manifest(self):
        self.release_scenario({'stdout': KUBECTL_OK})
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual(list(result), ['name', 'namespace', 'revision', 'status', 'chart', 'chartVersion',
                                        'objects', 'hidden', 'history', 'appVersion', 'lastDeployed'])
        self.assertNotIn('manifest', result)
        self.assertEqual([o['kind'] for o in result['objects']], ['Secret', 'ConfigMap'])
        self.assertEqual(result['objects'][0]['data'], {'password': '<hidden>', 'user': '<hidden>'})
        self.assertEqual(result['hidden'], [])

    def test_release_secret_value_is_never_in_the_response(self):
        nested = {'apiVersion': 'v1', 'kind': 'List', 'items': [SECRET_OBJ, {'apiVersion': 'v1', 'kind': 'List',
                                                                              'items': [SECRET_OBJ]}]}
        self.release_scenario({'stdout': kubectl_out(SECRET_OBJ, CONFIGMAP_OBJ) + json.dumps(nested)})
        resp = self.post(self.REL)
        self.assertEqual(resp.code, 200)
        for leaked in ('aHVudGVyMg', 'YWRtaW4', 'plain-text-token', 'c3VwZXI', 'last-applied', 'hunter2'):
            self.assertNotIn(leaked, resp.body.decode())

    def test_release_with_a_v1_list_answer(self):
        self.release_scenario({'stdout': json.dumps({'apiVersion': 'v1', 'kind': 'List',
                                                     'items': [SECRET_OBJ, CONFIGMAP_OBJ]})})
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual([o['kind'] for o in result['objects']], ['Secret', 'ConfigMap'])

    def test_release_with_a_nested_v1_list_answer(self):
        inner = {'apiVersion': 'v1', 'kind': 'List', 'items': [SECRET_OBJ]}
        self.release_scenario({'stdout': json.dumps({'apiVersion': 'v1', 'kind': 'List',
                                                     'items': [inner, CONFIGMAP_OBJ, inner]})})
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual([o['kind'] for o in result['objects']], ['Secret', 'ConfigMap', 'Secret'])
        self.assertNotIn('aHVudGVyMg', json.dumps(result))

    def test_release_nonzero_exit_with_partial_output_reports_hidden_parts(self):
        err = ('error: resource mapping not found for name: "c" namespace: "" from "STDIN": no matches for kind '
               '"Foo" in version "x/v1"\nensure CRDs are installed first\n')
        self.release_scenario({'rc': 1, 'stdout': KUBECTL_OK, 'stderr': err})
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual([o['kind'] for o in result['objects']], ['Secret', 'ConfigMap'])
        self.assertEqual(result['hidden'], [
            {'reason': 'an object of the unknown kind Foo (its CRD is not installed on the robot)'}])

    def test_release_garbage_from_kubectl_is_release_unparsable(self):
        for create in ({'stdout': 'this is not json'}, {'rc': 1, 'stderr': 'error: error parsing STDIN: boom'},
                       {'stdout': ''}):
            self.release_scenario(create)
            error = self.err(self.post(self.REL), 502, 'release_unparsable')
            self.assertNotIn('hunter2', json.dumps(error))

    def test_release_oversized_kubectl_output_is_too_large(self):
        self.release_scenario({'stdout_bytes': inspect_ops.KUBECTL_OUT_CAP + 10})
        self.err(self.post(self.REL), 413, 'too_large')

    def test_release_pretty_printed_output_over_the_manifest_cap_is_fine_when_compact_is_under(self):
        # kubectl indents: the raw stdout may be 4x MANIFEST_CAP, only the compact JSON is capped
        pad = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'big'},
               'data': {'k%d' % i: 'v' * 20 for i in range(60000)}}     # 120000 values
        raw = kubectl_out(pad)
        compact = len(json.dumps(pad, separators=(',', ':')))
        self.assertGreater(len(raw), inspect_ops.MANIFEST_CAP)
        self.assertLess(compact, inspect_ops.MANIFEST_CAP)
        self.release_scenario({'stdout': raw})
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual(result['objects'][0]['metadata']['name'], 'big')

    def test_release_kubectl_failures_that_are_not_about_the_manifest(self):
        self.release_scenario({'rc': 1, 'stderr': 'sudo: a password is required'})
        self.err(self.post(self.REL), 502, 'device_error')
        self.release_scenario({'rc': 255, 'stderr': 'access denied: device_offline (x)'})
        self.err(self.post(self.REL), 503, 'offline')
        self.release_scenario({'rc': 1, 'stderr': 'unable to recognize "STDIN": dial tcp: connection refused'})
        self.err(self.post(self.REL), 502, 'device_error')

    def test_release_manifest_command_exit_255_does_not_copy_stderr(self):
        self.release_scenario({'rc': 255, 'stderr': 'error: cannot unmarshal !!str hunter2 into Go value'})
        error = self.err(self.post(self.REL), 503, 'unavailable')
        self.assertEqual(error['message'], 'The ssh session to the robot ended.')
        self.assertNotIn('hunter2', json.dumps(error))

    def test_release_with_an_empty_manifest_asks_kubectl_nothing(self):
        for manifest in ('', '  \n\t\n'):
            self.release_scenario({'stdout': 'unused'}, manifest)
            result = self.body_of(self.post(self.REL))['result']
            self.assertEqual((result['objects'], result['hidden']), ([], []))
        self.assertEqual(self.create_calls(), [])
        # comments only: kubectl says so itself
        self.release_scenario({'rc': 1, 'stderr': 'error: no objects passed to create\n'}, '# Source: x\n')
        result = self.body_of(self.post(self.REL))['result']
        self.assertEqual(result['objects'], [])
        self.assertEqual(len(self.create_calls()), 1)

    def test_release_stdin_is_closed_after_the_manifest(self):
        # a kubectl that reads to EOF returns: nothing hangs on an open stdin (large manifest)
        big = 'a: ' + 'x' * (inspect_ops.MANIFEST_CAP - 100) + '\n'
        self.release_scenario({'stdout': KUBECTL_OK}, big)
        self.assertEqual(self.post(self.REL).code, 200)
        self.assertEqual(len(base64.b64decode(self.create_calls()[0]['stdin_b64'])), len(big))

    def test_release_for_another_record_is_a_device_error(self):
        # the Secret that comes back names another release than the one asked for
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': helm_release(MANIFEST, name='other')},
        ]})
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}),
                 502, 'device_error')

    def test_release_jobs_are_bounded(self):
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': helm_release(MANIFEST)},
            {'match': CREATE, 'stdout': KUBECTL_OK},
        ]})
        runner = self.app.settings['inspect_runner']
        body = {'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}
        runner._jobs = inspect_ops.MAX_RELEASE_JOBS      # earlier jobs are still running
        error = self.err(self.post(body), 429, 'busy')
        self.assertEqual(error['retryAfter'], 5)
        self.assertEqual(runner._jobs, inspect_ops.MAX_RELEASE_JOBS)
        runner._jobs = 0
        self.assertEqual(self.body_of(self.post(body))['result']['revision'], 3)
        self.assertEqual(runner._jobs, 0)                # the count goes back down when the job ends

    def test_release_job_count_returns_to_zero_when_a_job_raises(self):
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': helm_release(MANIFEST)},
            {'match': CREATE, 'stdout': KUBECTL_OK},
        ]})
        runner = self.app.settings['inspect_runner']
        body = {'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}
        for name in ('decode_checked', 'shape_release_objects'):
            orig = getattr(inspect_ops, name)
            try:
                for exc in (RuntimeError('x'), RecursionError('deep'), MemoryError()):
                    def boom(*a, **k):
                        raise exc
                    setattr(inspect_ops, name, boom)
                    for _ in range(3):
                        self.assertEqual(self.post(body).code, 500)
                        self.assertEqual(runner._jobs, 0, repr(exc))
            finally:
                setattr(inspect_ops, name, orig)
        self.assertEqual(self.body_of(self.post(body))['result']['revision'], 3)
        self.assertEqual(runner._jobs, 0)

    def test_deeply_nested_release_json_does_not_erode_the_job_bound(self):
        rel = '{"name":"nvr","namespace":"teknoir-demo","version":3,"manifest":"","x":%s%s}' % (
            '[' * 300000, ']' * 300000)
        data = base64.b64encode(base64.b64encode(gzip.compress(rel.encode()))).decode()
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': data},
        ]})
        runner = self.app.settings['inspect_runner']
        body = {'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}
        for _ in range(3):
            resp = self.post(body)
            self.assertIn(resp.code, (413, 502), resp.body)
            self.assertEqual(runner._jobs, 0)

    def test_release_op_oversized_body_gets_json_invalid(self):
        self.err(self.post(None, raw=json.dumps(dict(self.POD, pad='x' * 5000))), 400, 'invalid')

    def test_release_over_the_time_budget_is_too_large(self):
        self.app.settings['inspect_runner'].redact_budget = -1
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '3\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v3', 'stdout': helm_release(MANIFEST)},
        ]})
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}),
                 413, 'too_large')

    def test_release_too_large(self):
        self.scenario({'ops': [{'match': 'get secrets -l', 'stdout_bytes': inspect_ops.RELEASE_LIST_CAP + 10}]})
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr'}), 413, 'too_large')
        self.scenario({'ops': [{'match': 'get secrets -l', 'stdout': '1\tdeployed\n'},
                               {'match': 'sh.helm.release', 'stdout_bytes': inspect_ops.RELEASE_SECRET_CAP + 10}]})
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr'}), 413, 'too_large')

    def test_oversized_stdout_is_too_large_except_logs(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout_bytes': inspect_ops.POD_CAP + 10},
                               {'match': 'get events', 'stdout_bytes': inspect_ops.EVENTS_CAP + 10},
                               {'match': 'logs', 'stdout_bytes': inspect_ops.LOG_READ_CAP + 5000}]})
        self.err(self.post(self.POD), 413, 'too_large')
        self.err(self.post(dict(self.POD, op='events')), 413, 'too_large')
        data = self.body_of(self.post(dict(self.POD, op='logs')))
        self.assertTrue(data['result']['truncated']['bytes'])
        self.assertLessEqual(data['result']['bytes'], inspect_ops.LOG_LIMIT_BYTES)

    def test_device_errors_end_to_end(self):
        cases = [
            ('Error from server (NotFound): pods "nvr-1" not found', 404, 'not_found'),
            ('previous terminated container "c" in pod "nvr-1" not found', 404, 'no_previous'),
            ('container "c" in pod "nvr-1" is waiting to start: CrashLoopBackOff', 409, 'not_started'),
            ('sudo: a password is required', 502, 'device_error'),
            ('boom', 502, 'device_error'),
        ]
        for stderr, status, code in cases:
            self.scenario({'ops': [{'match': 'kubectl', 'rc': 1, 'stderr': stderr}]})
            self.err(self.post(dict(self.POD, op='logs')), status, code)

    def test_hub_denials_on_master_start(self):
        for stderr, status, code in (
                ('access denied: forbidden (this device is outside your organisation units)', 403, 'forbidden'),
                ('access denied: session_limit (5 sessions)', 429, 'session_limit'),
                ('access denied: device_offline (x)', 503, 'offline'),
                ('access denied: rate_limited', 429, 'busy'),
                ('Permission denied (publickey).', 503, 'unavailable')):
            self.scenario({'master': {'rc': 255, 'stderr': stderr}})
            self.err(self.post(self.POD), status, code)
        self.assertEqual(self.op_calls(), [])

    def test_garbage_from_device_is_device_error(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': 'not json'}]})
        self.err(self.post(self.POD), 502, 'device_error')
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '[1]'}]})
        self.err(self.post(self.POD), 502, 'device_error')


class TestMasters(InspectHTTPBase):
    def setUp(self):
        super().setUp()
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{"name":"p"}}'}]})

    def test_one_master_for_three_ops_of_one_user(self):
        for _ in range(3):
            self.assertEqual(self.post(self.POD).code, 200)
        self.assertEqual(len(self.master_calls()), 1)
        self.assertEqual(len(self.op_calls()), 3)

    def test_argv_shape(self):
        self.assertEqual(self.post(self.POD).code, 200)
        master = self.master_calls()[0]['argv']
        op = self.op_calls()[0]['argv']
        cfg = make_config()
        user_dir = [d for d in os.listdir(self.base_dir) if d.startswith('u-')][0]
        cp = os.path.join(self.base_dir, user_dir, 'cm')
        kh = os.path.join(self.base_dir, user_dir, 'known_hosts')
        opts = cfg.ssh_options(ALICE, kh)
        self.assertEqual(op, opts + ['-T', '-o', 'BatchMode=yes', '-S', cp, '-o', 'ControlMaster=no',
                                     'teknoir@cam-1', '--', inspect_ops.remote_command(
                                         inspect_ops.KUBECTL + ['-n', 'teknoir-demo', 'get', 'pod', 'nvr-1',
                                                                '-o', 'json'])])
        self.assertEqual(master, opts + ['-T', '-o', 'BatchMode=yes', '-S', cp, '-o', 'ControlMaster=yes',
                                         '-o', 'ControlPersist=60', '-N', '-f', 'teknoir@cam-1'])
        self.assertIn('--on-behalf-of alice@example.com', ' '.join(op))
        self.assertIn('StrictHostKeyChecking=yes', op)
        self.assertNotIn('%', cp)

    def test_two_users_two_control_paths(self):
        self.assertEqual(self.post(self.POD, user=ALICE).code, 200)
        self.assertEqual(self.post(self.POD, user=BOB).code, 200)
        paths = {c['argv'][c['argv'].index('-S') + 1] for c in self.master_calls()}
        self.assertEqual(len(paths), 2)
        self.assertEqual(len(self.master_calls()), 2)
        for path in paths:
            self.assertEqual(os.path.dirname(os.path.dirname(path)), self.base_dir)
        self.assertEqual(stat.S_IMODE(os.stat(self.base_dir).st_mode), 0o700)
        for d in os.listdir(self.base_dir):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.base_dir, d)).st_mode), 0o700)
        # each user's ops carry their own identity
        ops = {c['argv'][c['argv'].index('-S') + 1]: ' '.join(c['argv']) for c in self.op_calls()}
        self.assertEqual(sum('--on-behalf-of alice@example.com' in v for v in ops.values()), 1)
        self.assertEqual(sum('--on-behalf-of bob@example.com' in v for v in ops.values()), 1)

    def test_stale_socket_recovered(self):
        self.assertEqual(self.post(self.POD).code, 200)
        self.assertEqual(len(self.master_calls()), 1)
        os.environ['FAKE_SSH_DIR'] = self.work
        self.scenario({'check_rc': 255, 'ops': [{'match': 'get pod', 'stdout': '{"metadata":{"name":"p"}}'}]})
        self.assertEqual(self.post(self.POD).code, 200)
        masters = self.master_calls()
        self.assertEqual(len(masters), 2)
        self.assertFalse(masters[1]['cp_existed'], 'the stale socket must be removed before a new master starts')

    def test_master_is_not_restarted_while_alive(self):
        self.assertEqual(self.post(self.POD).code, 200)
        self.assertEqual(self.post(self.POD).code, 200)
        checks = [c for c in self.calls() if '-O' in c['argv']]
        self.assertEqual(len(checks), 2)
        self.assertEqual(len(self.master_calls()), 1)

    def test_sweep_removes_dirs_of_dead_masters_and_close_exits_all(self):
        runner = self.app.settings['inspect_runner']
        self.assertEqual(self.post(self.POD, user=ALICE).code, 200)
        self.assertEqual(self.post(self.POD, user=BOB).code, 200)
        dirs = [os.path.join(self.base_dir, d) for d in os.listdir(self.base_dir)]
        self.assertEqual(len(dirs), 2)
        alice_dir = runner._user_dir(ALICE)
        os.unlink(os.path.join(alice_dir, 'cm'))           # ControlPersist expired
        self.io_loop.run_sync(runner.sweep)
        self.assertFalse(os.path.exists(alice_dir))
        bob_dir = runner._user_dir(BOB)
        self.assertTrue(os.path.exists(bob_dir))
        self.assertEqual(list(runner.states), [BOB])
        self.io_loop.run_sync(runner.close)
        self.assertGreaterEqual(len(self.exit_calls()), 1)
        self.assertFalse(os.path.exists(bob_dir))

    def test_orphan_dirs_swept(self):
        runner = self.app.settings['inspect_runner']
        os.makedirs(os.path.join(self.base_dir, 'u-deadbeefdeadbeef'), mode=0o700)
        os.makedirs(os.path.join(self.base_dir, 'other'), mode=0o700)
        self.io_loop.run_sync(runner.sweep)
        self.assertFalse(os.path.exists(os.path.join(self.base_dir, 'u-deadbeefdeadbeef')))
        self.assertTrue(os.path.exists(os.path.join(self.base_dir, 'other')))


class TestLimits(unittest.TestCase, FakeSSHMixin):
    """Runner level, so that concurrent requests are easy to start."""

    def setUp(self):
        self.setup_fake()

    def runner(self, **kw):
        return inspect_ops.InspectRunner(make_config(), ssh=self.ssh, base_dir=self.base_dir, **kw)

    def req(self, op='pod', **kw):
        return inspect_ops.parse_request(dict({'v': 1, 'op': op, 'namespace': 'n', 'pod': 'p'}, **kw))

    def test_third_concurrent_op_of_a_user_is_busy(self):
        self.scenario({'ops': [{'match': 'get pod', 'sleep': 1.5, 'stdout': '{"metadata":{}}'}]})

        async def go():
            r = self.runner(slot_wait=0.3)
            tasks = [asyncio.ensure_future(r.execute(ALICE, self.req())) for _ in range(3)]
            res = await asyncio.gather(*tasks, return_exceptions=True)
            await r.close()
            return res
        res = asyncio.run(go())
        failures = [x for x in res if isinstance(x, inspect_ops.Failure)]
        self.assertEqual([f.code for f in failures], ['busy'])
        self.assertEqual(failures[0].retry_after, 5)
        self.assertEqual(sum(isinstance(x, tuple) for x in res), 2)

    def test_global_slots(self):
        self.scenario({'ops': [{'match': 'get pod', 'sleep': 1.5, 'stdout': '{"metadata":{}}'}]})

        async def go():
            r = self.runner(slot_wait=0.3, max_concurrent=1)
            res = await asyncio.gather(r.execute(ALICE, self.req()), r.execute(BOB, self.req()),
                                       return_exceptions=True)
            await r.close()
            return res
        res = asyncio.run(go())
        self.assertEqual(sum(isinstance(x, inspect_ops.Failure) and x.code == 'busy' for x in res), 1)
        self.assertEqual(sum(isinstance(x, tuple) for x in res), 1)

    def test_other_users_are_not_blocked_by_one_user(self):
        self.scenario({'ops': [{'match': 'get pod', 'sleep': 0.5, 'stdout': '{"metadata":{}}'}]})

        async def go():
            r = self.runner(slot_wait=0.2)
            res = await asyncio.gather(*[r.execute(ALICE, self.req()) for _ in range(2)],
                                       r.execute(BOB, self.req()), return_exceptions=True)
            await r.close()
            return res
        self.assertTrue(all(isinstance(x, tuple) for x in asyncio.run(go())))

    def test_timeout_kills_the_process(self):
        self.scenario({'ops': [{'match': 'get pod', 'sleep': 30, 'stdout': '{}'}]})

        async def go():
            r = self.runner(op_timeout=1.5)
            try:
                await r.execute(ALICE, self.req())
            except inspect_ops.Failure as f:
                return f
            finally:
                await r.close()
        started = time.monotonic()
        f = asyncio.run(go())
        self.assertEqual(f.code, 'timeout')
        self.assertLess(time.monotonic() - started, 10)
        pid = self.op_calls()[0]['pid']
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(inspect_ops.STATUS['timeout'], 504)

    def test_rate_backstop(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{}}'}]})

        async def go():
            r = self.runner(rate_per_min=3)
            out = []
            for _ in range(4):
                try:
                    out.append(await r.execute(ALICE, self.req()))
                except inspect_ops.Failure as f:
                    out.append(f)
            bob = await r.execute(BOB, self.req())
            await r.close()
            return out, bob
        out, bob = asyncio.run(go())
        self.assertEqual([type(x).__name__ for x in out], ['tuple', 'tuple', 'tuple', 'Failure'])
        self.assertEqual(out[3].code, 'busy')

    def test_master_cap_evicts_least_recently_used(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{}}'}]})
        users = ['u%d@example.com' % i for i in range(4)]

        async def go():
            r = self.runner(max_masters=3)
            first_dir = None
            for u in users:
                await r.execute(u, self.req())
                if first_dir is None:
                    first_dir = r._user_dir(u)
            states = list(r.states)
            evicted_dir_exists = os.path.exists(first_dir)
            await r.close()
            return states, evicted_dir_exists
        states, exists = asyncio.run(go())
        self.assertEqual(states, users[1:])
        self.assertFalse(exists)
        self.assertGreaterEqual(len(self.exit_calls()), 1)

    def test_evicted_users_late_cleanup_does_not_touch_their_new_state(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': '{"metadata":{}}'}]})
        users = ['u%d@example.com' % i for i in range(3)]

        async def go():
            r = self.runner(max_masters=2)
            await r.execute(users[0], self.req())
            await r.execute(users[1], self.req())
            old_dir = r._user_dir(users[0])
            orig = r._close_state
            gate = asyncio.Event()

            async def slow_close(st):
                await gate.wait()           # the eviction's cleanup is still running
                await orig(st)
            r._close_state = slow_close
            evicting = asyncio.ensure_future(r.execute(users[2], self.req()))
            await asyncio.sleep(0.1)
            assert users[0] not in r.states
            # the evicted user comes back while the old state is still being closed; make room
            r.max_masters = 3
            await r.execute(users[0], self.req())
            new_dir = r.states[users[0]].dir
            known_hosts_dir_ok = os.path.isdir(new_dir)
            gate.set()
            await evicting
            result = (old_dir, new_dir, os.path.exists(old_dir), os.path.isdir(new_dir), known_hosts_dir_ok)
            await r.close()
            return result
        old_dir, new_dir, old_exists, new_exists, _ = asyncio.run(go())
        self.assertNotEqual(old_dir, new_dir)
        self.assertFalse(old_exists)
        self.assertTrue(new_exists, 'the late cleanup removed the successor state directory')

    def test_master_cap_all_busy(self):
        self.scenario({'ops': [{'match': 'get pod', 'sleep': 1.0, 'stdout': '{"metadata":{}}'}]})

        async def go():
            r = self.runner(max_masters=1, slot_wait=0.2)
            a = asyncio.ensure_future(r.execute(ALICE, self.req()))
            await asyncio.sleep(0.3)
            try:
                await r.execute(BOB, self.req())
            except inspect_ops.Failure as f:
                res = f
            await a
            await r.close()
            return res
        self.assertEqual(asyncio.run(go()).code, 'busy')

    def test_missing_ssh_binary_is_internal(self):
        async def go():
            r = inspect_ops.InspectRunner(make_config(), ssh='/nonexistent/ssh', base_dir=self.base_dir)
            try:
                await r.execute(ALICE, self.req())
            except inspect_ops.Failure as f:
                return f
            finally:
                await r.close()
        self.assertEqual(asyncio.run(go()).code, 'internal')

    def test_master_start_timeout_is_timeout(self):
        # the fake hangs in master start through a scenario sleep on the master call
        with open(self.ssh) as fh:
            src = fh.read()
        src = src.replace("m = sc.get('master', {})", "m = sc.get('master', {})\n    time.sleep(m.get('sleep', 0))")
        with open(self.ssh, 'w') as fh:
            fh.write(src)
        self.scenario({'master': {'sleep': 30}})

        async def go():
            r = self.runner(master_timeout=0.7)
            try:
                await r.execute(ALICE, self.req())
            except inspect_ops.Failure as f:
                return f
            finally:
                await r.close()
        self.assertEqual(asyncio.run(go()).code, 'timeout')

    def test_max_masters_is_sized_for_the_container(self):
        self.assertEqual(inspect_ops.MAX_MASTERS, 6)


class TestRealListener(FakeSSHMixin, AsyncTestCase):
    """Through start_inspect_listener: tornado's connection-level limits apply here."""

    def setUp(self):
        super().setUp()
        self.setup_fake()
        sock, self.port = bind_unused_port()
        sock.close()
        started = inspect_ops.start_inspect_listener(make_config(), [PRINCIPAL], self.port,
                                                     ssh=self.ssh, base_dir=self.base_dir)
        self.app, self.sweeper = started

    def tearDown(self):
        self.sweeper.stop()
        self.io_loop.run_sync(self.app.settings['inspect_runner'].close)
        super().tearDown()

    async def post(self, raw):
        client = AsyncHTTPClient()
        return await client.fetch(
            'http://127.0.0.1:%d/inspect/v1/op' % self.port, method='POST', body=raw, raise_error=False,
            headers={'Content-Type': 'application/json', 'X-Inspect-User': ALICE,
                     'X-Forwarded-Client-Cert': XFCC_OK})

    @gen_test
    async def test_body_over_4_kib_gets_the_json_invalid_answer(self):
        resp = await self.post(json.dumps({'v': 1, 'op': 'pod', 'namespace': 'n', 'pod': 'p',
                                           'pad': 'x' * 8192}))
        self.assertEqual(resp.code, 400)
        self.assertEqual(resp.headers['Content-Type'], 'application/json')
        self.assertEqual(json.loads(resp.body)['error']['code'], 'invalid')

    @gen_test
    async def test_normal_request_works(self):
        self.scenario({'ops': [{'match': 'get pod', 'stdout': json.dumps({'metadata': {'name': 'p'}})}]})
        resp = await self.post(json.dumps({'v': 1, 'op': 'pod', 'namespace': 'n', 'pod': 'p'}))
        self.assertEqual(resp.code, 200, resp.body)


class TestWiring(unittest.TestCase):
    def test_build_command_unchanged_and_split(self):
        cfg = make_config()
        kh = '/tmp/wgterm-x/known_hosts'
        self.assertEqual(cfg.build_command(ALICE, kh), ['ssh'] + cfg.ssh_options(ALICE, kh) + [cfg.destination])
        self.assertEqual(cfg.destination, 'teknoir@cam-1')
        self.assertNotIn('teknoir@cam-1', cfg.ssh_options(ALICE, kh))
        self.assertEqual(cfg.ssh_options(ALICE, kh)[:2], ['-o', 'LogLevel=ERROR'])
        with self.assertRaises(ValueError):
            cfg.ssh_options('x@y.z; reboot', kh)

    def test_listener_not_started_without_principals(self):
        self.assertIsNone(inspect_ops.start_inspect_listener(make_config(), [], 0))
        self.assertIsNone(inspect_ops.start_inspect_listener(make_config(), inspect_ops.parse_principals(''), 0))

    def test_module_does_not_shadow_stdlib(self):
        import inspect
        self.assertTrue(hasattr(inspect, 'signature'))


class TestMainApp8080HasNoInspectRoutes(AsyncHTTPTestCase):
    def get_app(self):
        manager = wg_mode.WireGuardTermManager(make_config(), max_terminals=10)
        self.manager = manager
        from common_demo_stuff import TEMPLATE_DIR, STATIC_DIR
        return tornado.web.Application(
            wg_mode.make_handlers(manager, named.ActivityHandler, {'path': STATIC_DIR}),
            template_path=TEMPLATE_DIR, term_manager=manager, last_used_time=0)

    def tearDown(self):
        self.io_loop.run_sync(self.manager.kill_all)
        super().tearDown()

    def test_inspect_paths_404_on_the_terminal_listener(self):
        for path in ('/inspect/v1/op', '/inspect/v1/healthz'):
            for method in ('GET', 'POST'):
                resp = self.fetch(path, method=method, body='{}' if method == 'POST' else None,
                                  headers={'X-Inspect-User': ALICE, 'X-Forwarded-Client-Cert': XFCC_OK,
                                           'Sec-Fetch-Site': 'none'}, follow_redirects=False)
                self.assertEqual(resp.code, 404, (path, method))

    def test_named_main_wires_the_listener_only_in_wireguard_mode(self):
        import inspect as std_inspect
        src = std_inspect.getsource(named.main)
        self.assertIn('if wireguard:', src)
        self.assertIn('start_inspect_listener', src)
        # deadend mode never reaches it: the call sits under `if wireguard:`
        block = src[src.index('inspect_listener = None'):]
        self.assertTrue(block.splitlines()[1].strip().startswith('if wireguard'))


if __name__ == '__main__':
    unittest.main()
