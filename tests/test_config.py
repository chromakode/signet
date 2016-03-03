import unittest
from mock import (
    patch,
    mock_open,
)
import json

import signet
from tests import (
    fixtures,
    TEST_KEYID,
    TEST_KEYRING,
    TEST_SECRET_KEYRING,
)


class TestConfig(unittest.TestCase):
    def test_missing_files(self):
        c = signet.Config(config_dir=fixtures.path('.'))
        with self.assertRaisesRegexp(signet.NoConfigError, '^Could not find'):
            c.save()

    def test_save_and_load_config(self):
        c = signet.Config(config_dir=fixtures.path('signet'), keyid=TEST_KEYID)
        c.init_defaults()
        c['secret_keyring'] = TEST_SECRET_KEYRING
        self.assertEqual(c['secret_keyring'], TEST_SECRET_KEYRING)
        c['test'] = True
        self.assertTrue(c['test'])

        with patch('os.path.exists', return_value=True):
            with patch('__builtin__.open', mock_open()) as open_write_mock:
                c.save()

        open_write_mock.assert_called_once_with(fixtures.path('signet/config'), 'w')
        attestation_text = ''.join(call[0][0] for call in open_write_mock.return_value.write.call_args_list)
        attestation = json.loads(attestation_text)

        self.assertEqual(attestation['data']['version'], signet.__version__)
        signet.verify_attestation(attestation, TEST_KEYRING)

        c2 = signet.Config(config_dir=fixtures.path('signet'))

        with patch('os.path.exists', return_value=True):
            with patch('__builtin__.open', mock_open(read_data=attestation_text)) as open_read_mock:
                c2.load()

        open_read_mock.assert_called_once_with(fixtures.path('signet/config'))
        self.assertEqual(c2.config, c.config)

    def test_new_config_no_key(self):
        c = signet.Config(config_dir=fixtures.path('signet'))
        with self.assertRaisesRegexp(signet.NoConfigError, 'No key specified'):
            c.save()
