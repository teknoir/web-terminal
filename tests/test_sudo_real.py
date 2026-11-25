"""The inspect ops against a real sshd and a real sudo (a throwaway container), through the real
ssh client and one ControlMaster per user, exactly as the pod runs them. Opt in:

    WT_SUDO_REAL=1 scripts/test.sh tests/test_sudo_real.py

It needs docker and an ssh client on the machine. WT_SUDO_REAL_BASE picks another device OS
(default debian:trixie-slim; ubuntu:22.04 and ubuntu:20.04 have older sudo). The unit tests (test_inspect.py) use a fake ssh
and cannot tell what sudo does with its stdin, its login cache or a wrong password; this does.
"""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

import inspect_ops
from test_inspect import helm_release

ALICE = 'alice@example.com'
BASE = os.environ.get('WT_SUDO_REAL_BASE') or 'debian:trixie-slim'
IMAGE = 'web-terminal-sudo-real:' + BASE.replace(':', '-').replace('/', '-')
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sudo_real')
PW = 'Corr3ct horse $(id) `x` \'"; å'
WRONG = 'not the password'
# JSON is YAML: the stand-in kubectl answers the manifest command with its stdin, so the objects
# of the release are exactly what arrived there.
MANIFEST = json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'cm', 'namespace': 'n'},
                       'data': {'first': 'line one\nline two\n', 'second': 'x'}}, indent=2) + '\n'


def docker(*args, **kwargs):
    return subprocess.run(['docker'] + list(args), check=True, capture_output=True, **kwargs)


class DeviceConfig:
    """What InspectRunner needs of the WireGuard config, pointed at the container's sshd."""

    def __init__(self, user, port, key):
        self.destination = '%s@127.0.0.1' % user
        self.port, self.key = port, key

    def ssh_options(self, email, known_hosts_file):
        return ['-o', 'LogLevel=ERROR', '-o', 'UserKnownHostsFile=' + known_hosts_file,
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'IdentitiesOnly=yes',
                '-p', str(self.port), '-i', self.key]


@unittest.skipUnless(os.environ.get('WT_SUDO_REAL') == '1' and shutil.which('docker') and shutil.which('ssh'),
                     'set WT_SUDO_REAL=1 (needs docker and ssh)')
class TestRealSudo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix='sudo-real-')
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        cls.key = os.path.join(cls.work, 'id')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', cls.key], check=True)
        docker('build', '-q', '--build-arg', 'BASE=' + BASE, '-t', IMAGE, HERE)
        cls.container = docker('run', '-d', '--rm', '-p', '127.0.0.1::22', IMAGE, 'sleep', '900').stdout.decode().strip()
        cls.addClassCleanup(subprocess.run, ['docker', 'rm', '-f', cls.container], capture_output=True)
        release = os.path.join(cls.work, 'release.b64')
        with open(release, 'w') as fh:
            fh.write(helm_release(MANIFEST, namespace='n'))
        docker('cp', release, cls.container + ':/opt/fake/release.b64')
        with open(cls.key + '.pub', 'rb') as fh:
            docker('exec', '-i', cls.container, '/opt/fake/setup.sh', PW, input=fh.read())
        cls.port = int(docker('port', cls.container, '22/tcp').stdout.decode().splitlines()[0].rsplit(':', 1)[1])
        for _ in range(50):
            probe = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                                    '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                                    '-o', 'IdentitiesOnly=yes', '-p', str(cls.port), '-i', cls.key,
                                    'pwbash@127.0.0.1', 'true'], capture_output=True)
            if probe.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise unittest.SkipTest('the test sshd did not come up: %r' % probe.stderr[-200:])

    def setUp(self):
        docker('exec', self.container, 'sh', '-c', ': > /var/log/sudo.log; rm -rf /run/sudo/ts/*')

    def sudo_log(self):
        return docker('exec', self.container, 'cat', '/var/log/sudo.log').stdout.decode()

    def run_ops(self, user, *bodies):
        """Each body as one op of ALICE on `user`'s login, one after the other on ONE runner (so one
        ssh master). Returns a list of (result, error) pairs and everything the runs logged."""
        base = tempfile.mkdtemp(prefix='run-', dir=self.work)

        async def go():
            runner = inspect_ops.InspectRunner(DeviceConfig(user, self.port, self.key), base_dir=base)
            out = []
            try:
                for body in bodies:
                    req = inspect_ops.parse_request(dict({'v': 1}, **body))
                    try:
                        result, _ = await runner.execute(ALICE, req)
                        out.append((result, None))
                    except inspect_ops.Failure as f:
                        out.append((None, f))
            finally:
                await runner.close()
            return out
        with self.assertLogs(level='DEBUG') as cm:
            inspect_ops.logger.debug('start')
            answers = asyncio.run(go())
        return answers, '\n'.join(cm.output)

    POD = {'op': 'pod', 'namespace': 'n', 'pod': 'p'}
    REL = {'op': 'release', 'namespace': 'n', 'release': 'nvr'}

    def assert_clean(self, *texts):
        for text in texts:
            for secret in (PW, json.dumps(PW)[1:-1], WRONG):
                self.assertNotIn(secret, text)

    def assert_release(self, result):
        # the manifest arrived whole and alone: no password line before it, nothing eaten by sudo
        self.assertEqual(result['revision'], 3)
        self.assertEqual(result['hidden'], [])
        self.assertEqual(result['objects'], [json.loads(MANIFEST)])

    def test_password_sudo_reads_every_op_twice_on_one_master(self):
        for user in ('pwbash', 'pwzsh'):
            with self.subTest(user=user):
                self.setUp()
                with_pw = [dict(b, sudoPassword=PW) for b in (self.POD, self.REL, self.POD, self.REL)]
                answers, logs = self.run_ops(user, *with_pw)
                self.assertEqual([e and e.message for _, e in answers], [None] * 4)
                self.assertEqual(answers[0][0]['pod']['metadata']['name'], 'ran-as-uid-0')
                self.assertEqual(answers[2][0]['pod']['metadata']['name'], 'ran-as-uid-0')
                self.assert_release(answers[1][0])
                self.assert_release(answers[3][0])
                self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
                self.assertNotIn('incorrect password', self.sudo_log())

    def test_without_a_password_a_password_device_answers_as_it_always_did(self):
        answers, logs = self.run_ops('pwbash', self.POD, self.REL)
        for _, error in answers:
            self.assertEqual((error.code, error.message),
                             ('device_error', 'The device login user cannot run kubectl through sudo.'))
        self.assertNotIn('incorrect password', self.sudo_log())      # `sudo -n` never tries one

    def test_a_wrong_password_is_one_failed_attempt_and_no_manifest_line_is_a_guess(self):
        for user in ('pwbash', 'pwzsh'):
            with self.subTest(user=user):
                self.setUp()
                body = dict(self.REL, sudoPassword=WRONG)
                answers, logs = self.run_ops(user, body, body, dict(self.POD, sudoPassword=WRONG))
                for _, error in answers:
                    self.assertEqual((error.code, error.message),
                                     ('device_error', inspect_ops.SUDO_REJECTED_MESSAGE))
                log = self.sudo_log()
                self.assertEqual(log.count('incorrect password attempt'), 1, log)
                self.assertIn('1 incorrect password attempt', log)
                self.assert_clean(logs, log)

    def test_the_wrapper_itself_sends_one_guess_however_long_the_stdin_is(self):
        # straight at the wrapper, without the pod's memory of the rejection
        command = inspect_ops.sudo_password_command(inspect_ops.kubectl_manifest_argv(None))
        ssh = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
               '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes',
               '-p', str(self.port), '-i', self.key]
        for user in ('pwbash', 'pwzsh'):
            with self.subTest(user=user):
                self.setUp()
                stdin = (WRONG + '\n' + PW + '\n' + PW + '\n' + MANIFEST).encode()
                done = subprocess.run(ssh + [user + '@127.0.0.1', '--', command], input=stdin, capture_output=True)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (inspect_ops.SUDO_REJECTED_RC, b'', b''))
                self.assertEqual(self.sudo_log().count('incorrect password attempt'), 1)
                done = subprocess.run(ssh + [user + '@127.0.0.1', '--', command], input=b'\n' + MANIFEST.encode(),
                                      capture_output=True)
                self.assertEqual((done.returncode, done.stdout, done.stderr),
                                 (inspect_ops.SUDO_NO_PASSWORD_RC, b'', b''))
                self.assertEqual(self.sudo_log().count('incorrect password attempt'), 1)
                done = subprocess.run(ssh + [user + '@127.0.0.1', '--', command],
                                      input=(PW + '\n' + MANIFEST).encode(), capture_output=True)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (0, MANIFEST.encode(), b''))

    def test_a_nopasswd_device_drops_the_password_line(self):
        for password in (PW, WRONG):
            with self.subTest(password=password):
                body = dict(self.REL, sudoPassword=password)
                answers, logs = self.run_ops('nopass', self.POD, body, dict(self.POD, sudoPassword=password), body)
                self.assertEqual([e and e.message for _, e in answers], [None] * 4)
                self.assert_release(answers[1][0])
                self.assert_release(answers[3][0])
                self.assertEqual(answers[2][0]['pod']['metadata']['name'], 'ran-as-uid-0')
                self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
                self.assertNotIn('incorrect password', self.sudo_log())

    def test_a_shared_sudo_login_never_passes_the_password_line_on(self):
        # after the first op sudo needs no password for this user at all: the line must still be
        # taken off the stdin, and a wrong one must not be tried
        body = dict(self.REL, sudoPassword=PW)
        answers, logs = self.run_ops('shared', body, body, dict(self.REL, sudoPassword=WRONG))
        self.assertEqual([e and e.message for _, e in answers], [None] * 3)
        for result, _ in answers:
            self.assert_release(result)
        self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
        self.assertNotIn('incorrect password', self.sudo_log())

    def test_a_device_that_keeps_no_sudo_login_gets_a_fixed_sentence(self):
        answers, logs = self.run_ops('nokeep', dict(self.POD, sudoPassword=PW), dict(self.REL, sudoPassword=PW))
        for _, error in answers:
            self.assertEqual((error.code, error.message), ('device_error', inspect_ops.SUDO_NOT_KEPT_MESSAGE))
        self.assertNotIn('incorrect password', self.sudo_log())
        self.assert_clean(logs)


if __name__ == '__main__':
    unittest.main()
