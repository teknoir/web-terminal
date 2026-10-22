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
import time
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
    def test_redaction(self):
        text = inspect_ops.redact_manifest(MANIFEST)
        for leaked in ('aHVudGVyMg', 'YWRtaW4', 'plain-text-token', 'leaked-in-broken-doc', 'dmFsdWU', 'c3VwZXI'):
            self.assertNotIn(leaked, text)
        self.assertIn('# Source: nvr/templates/secret.yaml', text)
        self.assertIn('# Source: nvr/templates/broken.yaml', text)
        self.assertIn('# <hidden: document could not be parsed>', text)
        self.assertIn('# keep this comment', text)               # untouched documents keep their text
        self.assertIn('LOG_LEVEL: info', text)
        self.assertIn('visible', text)                           # ConfigMap item inside a SecretList stays
        self.assertEqual(text.count('<hidden>'), 5)              # 2 data + 1 stringData + annotation + list item
        import yaml
        docs = [d for d in yaml.safe_load_all(text) if d]
        secret = docs[0]
        self.assertEqual(secret['data'], {'password': '<hidden>', 'user': '<hidden>'})
        self.assertEqual(secret['stringData'], {'token': '<hidden>'})
        self.assertEqual(secret['metadata']['name'], 'nvr-db')
        self.assertEqual(list(secret)[:3], ['apiVersion', 'kind', 'metadata'])   # order kept
        self.assertEqual(docs[-1]['items'][0]['data'], {'k': '<hidden>'})

    def test_secret_with_odd_shapes(self):
        text = inspect_ops.redact_manifest('---\nkind: Secret\ndata: not-a-map\nbinaryData:\n  a: AAAA\n')
        self.assertNotIn('not-a-map', text)
        self.assertNotIn('AAAA', text)

    def test_multi_document_chunk_fails_closed(self):
        text = inspect_ops.redact_manifest('--- !!map\nkind: Secret\ndata: {a: SECRETVALUE}\n--- !!map\nb: 1\n')
        self.assertNotIn('SECRETVALUE', text)

    def test_redacted_manifest_over_cap(self):
        big = '---\nkind: ConfigMap\ndata:\n  k: "%s"\n' % ('x' * (inspect_ops.MANIFEST_CAP + 10))
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.redact_manifest(big)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_decode_drops_everything_else(self):
        rows = [(3, 'deployed'), (2, 'superseded'), (1, 'superseded')]
        for gz in (True, False):
            out = inspect_ops.shape_release(helm_release(MANIFEST, gz=gz), rows, 'nvr', 'teknoir-demo', 3)
            self.assertEqual(set(out), {'name', 'namespace', 'revision', 'status', 'chart', 'chartVersion',
                                        'appVersion', 'lastDeployed', 'manifest', 'history'})
            self.assertEqual((out['name'], out['revision'], out['status'], out['chart'], out['chartVersion'],
                              out['appVersion'], out['lastDeployed']),
                             ('nvr', 3, 'deployed', 'nvr', '0.4.2', '1.2.0', '2026-10-02T10:00:00Z'))
            self.assertEqual(out['history'][0], {'revision': 3, 'status': 'deployed'})
            blob = json.dumps(out)
            for leaked in ('hunter2', 'chart-default-pw', 'SECRET NOTE', 'secret-hook', 'templates/x.yaml'):
                self.assertNotIn(leaked, blob)

    def test_history_capped_at_20(self):
        rows = [(i, 'superseded') for i in range(30, 0, -1)]
        self.assertEqual(len(inspect_ops.shape_release(helm_release(MANIFEST), rows, 'nvr', 'teknoir-demo', 3)['history']), 20)

    def test_gzip_bomb_is_too_large(self):
        bomb = gzip.compress(b'{"manifest": "' + b'a' * (inspect_ops.RELEASE_JSON_CAP + 1000) + b'"}', 1)
        data = base64.b64encode(base64.b64encode(bomb)).decode()
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.decode_release(data)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_large_manifest_fails_fast_before_parsing(self):
        # compressible and over the cap: must be refused without splitting or parsing it
        doc = '---\nkind: ConfigMap\ndata:\n  k: "%s"\n' % ('x' * 1000)
        manifest = doc * ((inspect_ops.MANIFEST_CAP // len(doc)) + 10)
        data = helm_release(manifest)
        self.assertLess(len(data), 200000)
        orig = inspect_ops.redact_manifest

        def boom(_):
            raise AssertionError('manifest was parsed')
        inspect_ops.redact_manifest = boom
        try:
            started = time.monotonic()
            with self.assertRaises(inspect_ops.Failure) as cm:
                inspect_ops.shape_release(data, [(3, 'deployed')], 'nvr', 'teknoir-demo', 3)
        finally:
            inspect_ops.redact_manifest = orig
        self.assertEqual(cm.exception.code, 'too_large')
        self.assertLess(time.monotonic() - started, 2)

    def test_sensitive_documents_are_found_without_composing_them(self):
        cases = {
            'flow': 'kind: Secret\ndata: {a: LEAK1}\n',
            'quoted': '"kind": "Secret"\ndata:\n  a: LEAK1\n',
            'kind last': 'metadata:\n  name: x\ndata:\n  a: LEAK1\nkind: Secret\n',
            'duplicate kind': 'kind: Secret\ndata:\n  a: LEAK1\nkind: ConfigMap\n',
            'merge key': 'base: &b {kind: Secret}\n<<: *b\ndata:\n  a: LEAK1\n',
            'alias key': '&k kind: ignored\n*k : Secret\ndata:\n  a: LEAK1\n',
            'kind is an alias': 'x: &k Secret\nkind: *k\ndata:\n  a: LEAK1\n',
            'list': 'kind: SecretList\nitems:\n- kind: Secret\n  data: {a: LEAK1}\n',
            'second document': 'kind: ConfigMap\n...\n--- !!map\nkind: Secret\ndata: {a: LEAK1}\n',
        }
        for name, body in cases.items():
            text = inspect_ops.redact_manifest('---\n# Source: x\n' + body)
            self.assertNotIn('LEAK1', text, name)
            self.assertIn('# Source: x', text, name)

    def test_plain_documents_pass_as_text_without_being_loaded(self):
        docs = ['kind: ConfigMap\ndata: {kind: Secret}\n',                  # nested kind is not the kind
                'kind: Deployment\nspec:\n  kind: Secret\n',
                '- kind: Secret\n  data: {a: visible}\n',                   # a sequence document
                'just a scalar\n']
        orig = inspect_ops.yaml.load

        def boom(*a, **k):
            raise AssertionError('document was loaded')
        inspect_ops.yaml.load = boom
        try:
            for body in docs:
                text = inspect_ops.redact_manifest('---\n' + body)
                self.assertEqual(text, '---\n' + body.strip('\n') + '\n')
        finally:
            inspect_ops.yaml.load = orig

    def test_secret_document_over_the_load_cap_is_hidden(self):
        body = 'kind: Secret\ndata:\n  a: LEAK1\n  pad: "%s"\n' % ('x' * inspect_ops.SECRET_DOC_CAP)
        text = inspect_ops.redact_manifest('---\n# Source: big\n' + body)
        self.assertNotIn('LEAK1', text)
        self.assertIn('# Source: big', text)
        self.assertIn('# <hidden: document too large to redact>', text)
        small = inspect_ops.redact_manifest('---\nkind: Secret\ndata:\n  a: LEAK1\n')
        self.assertIn('a: <hidden>', small)

    def test_budget_stops_the_redaction(self):
        manifest = ''.join('---\nkind: ConfigMap\nmetadata: {name: n%d}\n' % i for i in range(2000))
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.redact_manifest(manifest, deadline=time.monotonic() - 1)
        self.assertEqual(cm.exception.code, 'too_large')
        with self.assertRaises(inspect_ops.Failure) as cm:
            inspect_ops.shape_release(helm_release(manifest), [(3, 'deployed')], 'nvr', 'teknoir-demo', 3,
                                      budget=-1)
        self.assertEqual(cm.exception.code, 'too_large')

    def test_large_non_secret_documents_stay_within_memory_and_time(self):
        # A 4 MiB document of tiny items, sent as a few KiB of gzip, must not be composed:
        # measured before the streaming scan: ~700 MiB peak and 4.6 s for the flow variant.
        probe = textwrap.dedent('''\
            import resource, sys, time
            sys.path.insert(0, sys.argv[1])
            import inspect_ops, yaml
            variant = sys.argv[2]
            if variant == 'flow':
                body = 'kind: ConfigMap\\nx: [' + ','.join(['1'] * 1900000) + ']\\n'
            elif variant == 'block':
                body = 'kind: ConfigMap\\nx:\\n' + '- a\\n' * 1000000
            else:    # many tiny documents
                body = '---\\n'.join('a: 1\\n' for _ in range(400000))
            manifest = '---\\n' + body
            assert len(manifest) <= inspect_ops.MANIFEST_CAP, len(manifest)
            before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            started = time.monotonic()
            try:
                out = inspect_ops.redact_manifest(manifest, time.monotonic() + 30)
                ok = out.startswith('---\\nkind') or variant == 'tiny'
            except inspect_ops.Failure as f:
                ok = f.code == 'too_large'
            after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            print(ok, (after - before) // 1024, round(time.monotonic() - started, 2))
        ''')
        app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'app')
        for variant in ('flow', 'block', 'tiny'):
            out = subprocess.run([sys.executable, '-c', probe, app_dir, variant], capture_output=True,
                                 text=True, timeout=60, check=True).stdout.split()
            self.assertEqual(out[0], 'True', variant)
            self.assertLess(int(out[1]), 64, '%s grew by %s MiB' % (variant, out[1]))
            self.assertLess(float(out[2]), 5.0, '%s took %s s' % (variant, out[2]))

    def test_release_must_match_the_request(self):
        rows = [(3, 'deployed')]
        ok = inspect_ops.shape_release(helm_release(MANIFEST), rows, 'nvr', 'teknoir-demo', 3)
        self.assertIs(type(ok['revision']), int)
        for name, ns, rev in (('other', 'teknoir-demo', 3), ('nvr', 'elsewhere', 3), ('nvr', 'teknoir-demo', 2)):
            with self.assertRaises(inspect_ops.Failure) as cm:
                inspect_ops.shape_release(helm_release(MANIFEST), rows, name, ns, rev)
            self.assertEqual(cm.exception.code, 'device_error', (name, ns, rev))
        for version in (None, '3', 3.0, True):
            data = helm_release(MANIFEST, version=version)
            for rev in (3, 1):
                with self.assertRaises(inspect_ops.Failure) as cm:
                    inspect_ops.shape_release(data, rows, 'nvr', 'teknoir-demo', rev)
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
        ]})
        data = self.body_of(self.post(dict(self.POD, op='events')))
        self.assertEqual(data['result']['events'][0]['reason'], 'BackOff')
        data = self.body_of(self.post(dict(self.POD, op='logs', tail=10)))
        self.assertEqual(data['result']['container'], 'nvr')
        self.assertEqual(data['result']['lines'], 1)
        data = self.body_of(self.post({'v': 1, 'op': 'release', 'namespace': 'teknoir-demo', 'release': 'nvr'}))
        self.assertEqual(data['result']['revision'], 3)
        self.assertNotIn('hunter2', json.dumps(data))
        self.assertNotIn('aHVudGVyMg', json.dumps(data))

    def test_release_explicit_revision_and_missing(self):
        self.scenario({'ops': [
            {'match': 'get secrets -l', 'stdout': '1\tsuperseded\n2\tdeployed\n'},
            {'match': 'sh.helm.release.v1.nvr.v1', 'stdout': helm_release(MANIFEST, version=1, status='superseded', namespace='n')},
        ]})
        body = {'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr', 'revision': 1}
        self.assertEqual(self.body_of(self.post(body))['result']['revision'], 1)
        self.err(self.post(dict(body, revision=7)), 404, 'not_found')
        self.scenario({'ops': [{'match': 'get secrets -l', 'stdout': ''}]})
        self.err(self.post(dict(body, revision=1)), 404, 'not_found')
        self.err(self.post({'v': 1, 'op': 'release', 'namespace': 'n', 'release': 'nvr'}), 404, 'not_found')

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
