import json
import os
import shutil
import unittest

from mock import patch

import signet
from tests import (
    TEST_KEYID,
    TEST_KEYRING,
    fixtures,
)


class TestCLISetup(unittest.TestCase):
    def setUp(self):
        os.environ['GNUPGHOME'] = fixtures.path('gpg/')
        os.environ['SIG_DIR'] = fixtures.path('work/signet')

    def tearDown(self):
        del os.environ['GNUPGHOME']
        del os.environ['SIG_DIR']
        shutil.rmtree(fixtures.path('work/signet'))

    def test_integration(self):
        self.do_setup()
        self.do_attest_verify_ok()
        self.do_attest_verify_not_ok()

    def do_setup(self):
        with patch('sys.stdout') as stdout_mock:
            signet.SigCLI().run(['setup', TEST_KEYID[-8:]])

        stdout_mock.write.assert_any_call('With public key fingerprint: 9C75CB915794A44DD7697E21571D8816D9886717\n')
        self.assertTrue(os.path.isfile(fixtures.path('work/signet/config')))
        self.assertTrue(os.path.isfile(fixtures.path('work/signet/keyring.gpg')))
        self.assertTrue(os.path.isdir(fixtures.path('work/signet/repo')))
        self.assertTrue(os.path.isfile(fixtures.path('work/signet/repo/key.asc')))
        self.assertTrue(os.path.isfile(fixtures.path('work/signet/repo/repo.json')))
        self.assertTrue(os.path.isdir(fixtures.path('work/signet/remotes')))

        with open(fixtures.path('work/signet/config')) as f:
            config_attestation = json.load(f)
            signet.verify_attestation(config_attestation, keyring=TEST_KEYRING)

        self.assertEqual(config_attestation['key'], TEST_KEYID)

        with open(fixtures.path('work/signet/repo/repo.json')) as f:
            repo_attestation = json.load(f)
            signet.verify_attestation(repo_attestation, keyring=TEST_KEYRING)

        self.assertEqual(repo_attestation['key'], TEST_KEYID)

    def do_attest_verify_ok(self):
        with patch('sys.stdout') as attest1_stdout_mock:
            with patch('__builtin__.raw_input', side_effect=['yes', 'y', 'n', 'yes', 'test']) as attest1_input_mock:
                signet.SigCLI().run(['attest', fixtures.path('test.txt')])

        attest1_input_mock.assert_any_call('I have reviewed this file (yes/no): ')
        attest1_input_mock.assert_any_call('It performs as expected and is free of major flaws (yes/no): ')
        attest1_input_mock.assert_any_call('It performs as expected and is free of major flaws (yes/no): ')
        attest1_input_mock.assert_any_call('It performs as expected and is free of major flaws (yes/no): ')
        attest1_input_mock.assert_any_call('Comment: ')

        json_preview = ''.join(call[0][0] for call in attest1_stdout_mock.write.call_args_list[1:])
        parsed = json.loads(json_preview)

        self.assertEqual(parsed, {
            u'comment': u'test',
            u'ok': True,
            u'id': u'sha256:4dca0fd5f424a31b03ab807cbae77eb32bf2d089eed1cee154b3afed458de0dc',
            u'reviewed': True,
        })

        with patch('sys.stdout') as verify1_stdout_mock:
            signet.SigCLI().run(['verify', fixtures.path('test.txt')])

        self.assertRegexpMatches(verify1_stdout_mock.write.call_args[0][0], 'file [\w\/]+/tests/fixtures/test.txt is \x1b\[1;32mok\x1b\[0m.\n')

    def do_attest_verify_not_ok(self):
        with patch('sys.stdout'):
            with patch('__builtin__.raw_input', side_effect=['yes', 'no', 'test2']):
                signet.SigCLI().run(['attest', fixtures.path('test2.txt')])

        with self.assertRaises(SystemExit) as exit_exc:
            with patch('sys.stdout') as verify2_stdout_mock:
                signet.SigCLI().run(['verify', fixtures.path('test2.txt')])

        self.assertEqual(exit_exc.exception.code, 1)
        self.assertRegexpMatches(verify2_stdout_mock.write.call_args[0][0], 'file [\w\/]+/tests/fixtures/test2.txt is \x1b\[1;31mmarked bad\x1b\[0m!\n')
