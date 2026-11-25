"""The inspect ops against a real sshd and a real sudo (a throwaway container), through the real
ssh client and one ControlMaster per user, exactly as the pod runs them. Opt in:

    WT_SUDO_REAL=1 scripts/test.sh tests/test_sudo_real.py

It needs docker and an ssh client on the machine. WT_SUDO_REAL_BASE picks another device OS
(default debian:trixie-slim; ubuntu:22.04 and ubuntu:20.04 have older sudo) and WT_SUDO_REAL_SUDO the
package that provides sudo there (`sudo-rs` with ubuntu:26.04: the tests that need a sudoers setting
sudo-rs lacks are skipped). The unit tests (test_inspect.py)
use a fake ssh and cannot tell what sudo does with its stdin, its login cache, its input log or a
wrong password, or what pam_faillock counts; this does.
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
SUDO = os.environ.get('WT_SUDO_REAL_SUDO') or 'sudo'
IMAGE = 'web-terminal-sudo-real:' + (BASE + '-' + SUDO).replace(':', '-').replace('/', '-')
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sudo_real')
PW = 'Corr3ct horse $(id) `x` \'"; å'
WRONG = 'not the password'
# JSON is YAML: the stand-in kubectl answers the manifest command with its stdin, so the objects
# of the release are exactly what arrived there.
NEW_PW = 'changed on the device'
MANIFEST = json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'cm', 'namespace': 'n'},
                       'data': {'first': 'line one\nline two\n', 'second': 'x'}}, indent=2) + '\n'


# What a large release sends to kubectl: 2000 lines that must all arrive.
LONG = ''.join('line %04d of the manifest\n' % i for i in range(2000))


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
        docker('build', '-q', '--build-arg', 'BASE=' + BASE, '--build-arg', 'SUDO=' + SUDO, '-t', IMAGE, HERE)
        cls.container = docker('run', '-d', '--rm', '-p', '127.0.0.1::22', IMAGE, 'sleep', '900').stdout.decode().strip()
        cls.addClassCleanup(subprocess.run, ['docker', 'rm', '-f', cls.container], capture_output=True)
        release = os.path.join(cls.work, 'release.b64')
        with open(release, 'w') as fh:
            fh.write(helm_release(MANIFEST, namespace='n'))
        docker('cp', release, cls.container + ':/opt/fake/release.b64')
        with open(cls.key + '.pub', 'rb') as fh:
            docker('exec', '-i', cls.container, '/opt/fake/setup.sh', PW, input=fh.read())
        cls.features = set(docker('exec', cls.container, 'cat', '/opt/fake/features').stdout.decode().split())
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
        docker('exec', self.container, 'sh', '-c', ': > /var/log/sudo.log; rm -rf /run/sudo/ts/* /run/sudo-rs/ts/*; '
               'rm -rf /var/log/sudo-io /run/faillock/* /var/run/faillock/*')

    def need(self, *features):
        """Skips the test on a device without these (/opt/fake/features, a user of setup.sh)."""
        missing = [f for f in features if f not in self.features]
        if missing:
            self.skipTest('this device has no %s' % ', '.join(missing))

    @property
    def sudo_logs(self):
        """Whether sudo writes /var/log/sudo.log here (sudo-rs has no `logfile`)."""
        return 'sudo' in self.features

    def sudo_log(self):
        return docker('exec', self.container, 'cat', '/var/log/sudo.log').stdout.decode()

    def failed_logins(self, user):
        """The failed logins pam_faillock holds against `user`; None on a device without it."""
        if 'faillock' not in self.features:
            return None
        out = docker('exec', self.container, 'faillock', '--user', user).stdout.decode()
        return sum(1 for line in out.splitlines() if line.rstrip().endswith(' V'))

    def ssh(self, user, command, stdin=b''):
        return subprocess.run(self.SSH + ['-p', str(self.port), '-i', self.key, user + '@127.0.0.1', '--', command],
                              input=stdin, capture_output=True)

    SSH = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
           '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes']

    def wrapper(self, user, stdin):
        """The wrapper around the manifest command, straight over ssh: no pod, no memory."""
        return self.ssh(user, inspect_ops.sudo_password_command(inspect_ops.kubectl_manifest_argv(None)), stdin)

    def run_ops(self, user, *bodies):
        """Each body as one op of ALICE on `user`'s login, one after the other on ONE runner (so one
        ssh master). Returns a list of (result, error) pairs and everything the runs logged;
        `self.notes` is what each op did with its password (the `sudo=` of the pod's audit line)."""
        base = tempfile.mkdtemp(prefix='run-', dir=self.work)
        self.notes = []

        async def go():
            runner = inspect_ops.InspectRunner(DeviceConfig(user, self.port, self.key), base_dir=base)
            out = []
            try:
                for body in bodies:
                    req = inspect_ops.parse_request(dict({'v': 1}, **body))
                    note = {}
                    try:
                        result, _ = await runner.execute(ALICE, req, note)
                        out.append((result, None))
                    except inspect_ops.Failure as f:
                        out.append((None, f))
                    self.notes.append(note.get('sudo', '-'))
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
                self.assertEqual(self.notes, ['password'] * 4)
                self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
                self.assertNotIn('incorrect password', self.sudo_log())

    def test_without_a_password_a_password_device_answers_as_it_always_did(self):
        answers, logs = self.run_ops('pwbash', self.POD, self.REL)
        for _, error in answers:
            self.assertEqual((error.code, error.message),
                             ('device_error', 'The device login user cannot run kubectl through sudo.'))
        self.assertNotIn('incorrect password', self.sudo_log())      # `sudo -n` never tries one

    def test_a_wrong_password_is_no_failed_login_and_no_manifest_line_is_a_guess(self):
        for user in ('pwbash', 'pwzsh'):
            with self.subTest(user=user):
                self.setUp()
                body = dict(self.REL, sudoPassword=WRONG)
                answers, logs = self.run_ops(user, body, body, dict(self.POD, sudoPassword=WRONG))
                for _, error in answers:
                    self.assertEqual((error.code, error.message, error.sudo),
                                     ('device_error', inspect_ops.SUDO_REJECTED_MESSAGE, 'rejected'))
                self.assertEqual(self.notes, ['password', 'rejected', 'rejected'])
                log = self.sudo_log()
                # three requests, one command with the wrong password; PAM's helper refused it, so
                # sudo was never asked and nothing counts as a failed login
                self.assertNotIn('incorrect password', log)
                self.assertNotIn('COMMAND=validate', log)
                # (1: sudo 1.9.9 takes the refused plain `sudo -n`, which every read has always
                # run first, to PAM, and pam_faillock counts that)
                self.assertIn(self.failed_logins(user), (None, 0, 1))
                self.assert_clean(logs, log)

    def test_the_wrapper_itself_never_gives_sudo_a_wrong_password(self):
        # straight at the wrapper, without the pod's memory of the rejection
        for user in ('pwbash', 'pwzsh'):
            with self.subTest(user=user):
                self.setUp()
                for _ in range(4):                 # more than the 3 failed logins that lock an account
                    done = self.wrapper(user, (WRONG + '\n' + PW + '\n' + PW + '\n' + MANIFEST).encode())
                    self.assertEqual((done.returncode, done.stdout, done.stderr),
                                     (inspect_ops.SUDO_REJECTED_RC, b'', b''))
                done = self.wrapper(user, b'\n' + MANIFEST.encode())
                self.assertEqual((done.returncode, done.stdout, done.stderr),
                                 (inspect_ops.SUDO_NO_PASSWORD_RC, b'', b''))
                self.assertNotIn('incorrect password', self.sudo_log())
                self.assertNotIn('COMMAND=validate', self.sudo_log())
                self.assertIn(self.failed_logins(user), (None, 0))
                done = self.wrapper(user, (PW + '\n' + MANIFEST).encode())
                self.assertEqual((done.returncode, done.stdout, done.stderr), (0, MANIFEST.encode(), b''))
                self.assert_clean(self.sudo_log())

    def test_without_the_pam_helper_a_wrong_password_goes_to_sudo_once(self):
        # A device without unix_chkpwd: the wrapper leaves the decision to sudo. That is one guess
        # for sudo, however long the stdin is, and it is the case the pod's limits are built for
        # (one command at a time, a rejection is final): pam_faillock counts that one guess as 2
        # failed logins with sudo (it asks PAM again when its input has ended, and that counts
        # too) and as 1 with sudo-rs. A second such command would lock the account.
        # Taken from the login users only (root, so sshd, still runs it): the wrapper skips a
        # helper it may not execute.
        helper = docker('exec', self.container, 'sh', '-c', 'readlink -f "$(command -v unix_chkpwd)"').stdout.decode().strip()
        mode = docker('exec', self.container, 'stat', '-c', '%a', helper).stdout.decode().strip()
        docker('exec', self.container, 'chmod', 'o-rwx', helper)
        self.addCleanup(docker, 'exec', self.container, 'chmod', mode, helper)
        done = self.wrapper('pwbash', (WRONG + '\n' + PW + '\n' + PW + '\n' + MANIFEST).encode())
        self.assertEqual((done.returncode, done.stdout, done.stderr), (inspect_ops.SUDO_REJECTED_RC, b'', b''))
        if self.sudo_logs:
            self.assertEqual(self.sudo_log().count('incorrect password attempt'), 1, self.sudo_log())
            self.assertIn('1 incorrect password attempt', self.sudo_log())
        failed = self.failed_logins('pwbash')
        self.assertIn(failed, (None, 1, 2))
        print('\nfailed logins pam_faillock counts for one wrong password given to sudo (%s, %s): %s'
              % (BASE, SUDO, failed))
        # not locked: the right password works, through sudo alone
        done = self.wrapper('pwbash', (PW + '\n' + MANIFEST).encode())
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, MANIFEST.encode(), b''))
        self.assert_clean(self.sudo_log())
        # through the pod: one command carries it, the rest of the page does not
        self.setUp()
        body = dict(self.REL, sudoPassword=WRONG)
        answers, logs = self.run_ops('pwzsh', body, body, dict(self.POD, sudoPassword=WRONG))
        self.assertEqual([e and e.message for _, e in answers], [inspect_ops.SUDO_REJECTED_MESSAGE] * 3)
        self.assertEqual(self.notes, ['password', 'rejected', 'rejected'])
        if self.sudo_logs:
            self.assertEqual(self.sudo_log().count('incorrect password attempt'), 1)
        if failed is not None:
            # (+1: sudo 1.9.9 and the plain `sudo -n` before it)
            self.assertIn(self.failed_logins('pwzsh'), (failed, failed + 1))

    def test_a_locked_login_is_not_taken_for_a_wrong_password(self):
        # pam_faillock has locked the login (someone mistyped it in the Shell). The platform's
        # password is right, sudo refuses it all the same: that must not be remembered as a
        # rejection, or the device stays unreadable after the lock has ended.
        self.need('faillock')
        for _ in range(4):
            if self.failed_logins('lock') >= 3:
                break
            self.ssh('lock', "sudo -S -p '' -v", b'mistyped\n')
        self.assertGreaterEqual(self.failed_logins('lock'), 3)
        base = tempfile.mkdtemp(prefix='run-', dir=self.work)

        async def go():
            runner = inspect_ops.InspectRunner(DeviceConfig('lock', self.port, self.key), base_dir=base)
            out = []
            try:
                for unlock in (False, False, True):
                    if unlock:
                        docker('exec', self.container, 'faillock', '--user', 'lock', '--reset')
                    note = {}
                    req = inspect_ops.parse_request(dict({'v': 1}, sudoPassword=PW, **self.REL))
                    try:
                        out.append(((await runner.execute(ALICE, req, note))[0], note))
                    except inspect_ops.Failure as f:
                        out.append((f, note))
            finally:
                await runner.close()
            return out
        first, second, third = asyncio.run(go())
        for failure, note in (first, second):
            self.assertEqual((failure.code, failure.message, failure.sudo),
                             ('device_error', inspect_ops.SUDO_REFUSED_MESSAGE, None))
            self.assertEqual(note, {'sudo': 'password'})
        self.assert_release(third[0])

    def test_sudo_input_logging_leaves_the_manifest_for_kubectl(self):
        # `Defaults log_input`: sudo copies its stdin for the log, so a sudo that runs in the wrapper
        # before kubectl with the wrapper's stdin takes everything that waits there for kubectl
        # (a `sudo -n true` probe did: 0 of these 2000 lines arrived). None does.
        self.need('loginput', 'pwlog')
        for user in ('loginput', 'pwlog'):
            with self.subTest(user=user):
                for _ in range(3):
                    done = self.wrapper(user, (PW + '\n' + LONG).encode())
                    self.assertEqual(done.returncode, 0, done.stderr)
                    self.assertEqual(done.stdout.count(b'\n'), 2000)
                    self.assertEqual(done.stdout, LONG.encode())
        self.assert_clean(self.sudo_log())
        self.assertNotIn('incorrect password', self.sudo_log())
        # through the pod: the NOPASSWD user is read without the wrapper, the password user with it
        for user in ('loginput', 'pwlog'):
            with self.subTest(pod=user):
                body = dict(self.REL, sudoPassword=PW)
                answers, logs = self.run_ops(user, body, body)
                self.assertEqual([e and e.message for _, e in answers], [None] * 2)
                for result, _ in answers:
                    self.assert_release(result)
                self.assert_clean(logs)

    def test_a_nopasswd_device_never_gets_the_password_or_the_wrapper(self):
        for password in (PW, WRONG):
            with self.subTest(password=password):
                self.setUp()
                body = dict(self.REL, sudoPassword=password)
                answers, logs = self.run_ops('nopass', self.POD, body, dict(self.POD, sudoPassword=password), body)
                self.assertEqual([e and e.message for _, e in answers], [None] * 4)
                self.assert_release(answers[1][0])
                self.assert_release(answers[3][0])
                self.assertEqual(answers[2][0]['pod']['metadata']['name'], 'ran-as-uid-0')
                self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
                self.assertNotIn('incorrect password', self.sudo_log())
                self.assertEqual(self.notes, ['-', 'unused', 'unused', 'unused'])
                if self.sudo_logs:
                    # what sudo ran is what it runs for a request without the field: kubectl only
                    self.assertEqual(self.sudo_log().count('COMMAND='), 1 + 3 + 1 + 3)
                    self.assertEqual(self.sudo_log().count('COMMAND=/usr/local/bin/k3s kubectl'), 8)
                self.assertIn(self.failed_logins('nopass'), (None, 0))

    def test_a_nopasswd_rule_for_k3s_alone_is_read_as_before_whatever_the_password(self):
        # `NOPASSWD: /usr/local/bin/k3s` next to the %sudo password rule: `sudo -n true` asks for
        # a password there, `sudo -n k3s` does not. The read must not depend on the password.
        for password in (WRONG, PW):
            with self.subTest(password=password):
                self.setUp()
                body = dict(self.REL, sudoPassword=password)
                answers, logs = self.run_ops('k3sonly', dict(self.POD, sudoPassword=password), body, body)
                self.assertEqual([e and e.message for _, e in answers], [None] * 3)
                self.assertEqual(answers[0][0]['pod']['metadata']['name'], 'ran-as-uid-0')
                self.assert_release(answers[1][0])
                self.assert_release(answers[2][0])
                self.assertEqual(self.notes, ['unused'] * 3)
                self.assert_clean(logs, self.sudo_log())
                self.assertNotIn('incorrect password', self.sudo_log())
                if self.sudo_logs:
                    self.assertEqual(self.sudo_log().count('COMMAND='), 1 + 3 + 3)
                    self.assertEqual(self.sudo_log().count('COMMAND=/usr/local/bin/k3s kubectl'), 7)
                self.assertIn(self.failed_logins('k3sonly'), (None, 0))

    def test_a_password_changed_on_the_device_cannot_lock_the_account(self):
        # Pages are open, the password is accepted, and then it is changed on the device: every
        # request still carries the old one. pam_faillock locks the account at 3 failed logins.
        self.need('faillock')
        self.addCleanup(docker, 'exec', '-i', self.container, 'chpasswd', input=('lock:%s\n' % PW).encode())
        base = tempfile.mkdtemp(prefix='run-', dir=self.work)

        async def go():
            runner = inspect_ops.InspectRunner(DeviceConfig('lock', self.port, self.key), base_dir=base)

            async def op(email, password, body=self.POD):
                req = inspect_ops.parse_request(dict({'v': 1}, sudoPassword=password, **body))
                try:
                    return (await runner.execute(email, req))[0]
                except inspect_ops.Failure as f:
                    return f

            def together(password):
                return asyncio.gather(op(ALICE, password), op(ALICE, password, self.REL),
                                      op('bob@example.com', password), op('bob@example.com', password, self.REL))
            try:
                # one read first, as on a page that is open: it finds out that sudo asks, and that
                # it takes this password
                before = [await op(ALICE, PW)] + list(await together(PW))
                docker('exec', '-i', self.container, 'chpasswd', input=('lock:%s\n' % NEW_PW).encode())
                docker('exec', self.container, 'sh', '-c', 'rm -rf /run/sudo/ts/* /run/sudo-rs/ts/*')
                after = []
                for _ in range(3):
                    after += await together(PW)
                failed = self.failed_logins('lock')
                corrected = await together(NEW_PW)        # the platform's password was corrected
            finally:
                await runner.close()
            return before, after, failed, corrected
        with self.assertLogs(level='DEBUG') as cm:
            before, after, failed, corrected = asyncio.run(go())
        self.assertTrue(all(isinstance(x, dict) for x in before), before)
        self.assertEqual([(type(x), getattr(x, 'message', None)) for x in after],
                         [(inspect_ops.Failure, inspect_ops.SUDO_REJECTED_MESSAGE)] * 12)
        self.assertEqual(failed, 0)                       # the old password never reached sudo
        self.assertNotIn('incorrect password', self.sudo_log())
        # not locked: the new password is accepted at once
        self.assertTrue(all(isinstance(x, dict) for x in corrected), corrected)
        self.assertEqual(self.failed_logins('lock'), 0)
        self.assert_clean('\n'.join(cm.output))
        self.assertNotIn(NEW_PW, '\n'.join(cm.output))

    def test_a_shared_sudo_login_never_passes_the_password_line_on(self):
        # after the first op sudo needs no password for this user at all, whoever asks
        self.need('shared')
        body = dict(self.REL, sudoPassword=PW)
        answers, logs = self.run_ops('shared', body, body)
        self.assertEqual([e and e.message for _, e in answers], [None] * 2)
        self.assertEqual(self.notes, ['password', 'password'])
        for result, _ in answers:
            self.assert_release(result)
        self.assert_clean(logs, json.dumps([r for r, _ in answers]), self.sudo_log())
        # another pod, with a password the device would refuse: the plain run works on the login
        # sudo still has, so the password is not tried and not needed
        answers, logs = self.run_ops('shared', dict(self.REL, sudoPassword=WRONG), self.REL)
        self.assertEqual([e and e.message for _, e in answers], [None] * 2)
        self.assertEqual(self.notes, ['unused', '-'])
        for result, _ in answers:
            self.assert_release(result)
        self.assert_clean(logs, self.sudo_log())
        self.assertNotIn('incorrect password', self.sudo_log())
        self.assertIn(self.failed_logins('shared'), (None, 0))

    def test_a_device_that_keeps_no_sudo_login_gets_a_fixed_sentence(self):
        answers, logs = self.run_ops('nokeep', dict(self.POD, sudoPassword=PW), dict(self.REL, sudoPassword=PW))
        for _, error in answers:
            self.assertEqual((error.code, error.message), ('device_error', inspect_ops.SUDO_NOT_KEPT_MESSAGE))
        self.assertNotIn('incorrect password', self.sudo_log())
        self.assert_clean(logs)


if __name__ == '__main__':
    unittest.main()
