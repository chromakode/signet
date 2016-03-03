import unittest

import signet
from tests import (
    TEST_KEYRING,
    TEST_SECRET_KEYRING,
    TEST_KEYID,
    fixtures,
)


TEST_DATA = 'this is a test'


class TestGPG(unittest.TestCase):
    def test_sign_and_verify(self):
        signature = signet.gpg_sign(
            TEST_KEYID,
            TEST_DATA,
            keyring=TEST_KEYRING,
            secret_keyring=TEST_SECRET_KEYRING,
        )

        signet.gpg_verify(
            TEST_KEYID,
            TEST_DATA,
            signature,
            keyring=TEST_KEYRING,
        )

        with self.assertRaisesRegexp(signet.GPGInvalidSignatureError, 'Invalid signature'):
            signet.gpg_verify(
                TEST_KEYID,
                TEST_DATA,
                b'invalid:' + signature,
                keyring=TEST_KEYRING,
            )

        with self.assertRaisesRegexp(signet.GPGInvalidSignatureError, 'Invalid signature'):
            signet.gpg_verify(
                TEST_KEYID,
                'wrong:' + TEST_DATA,
                signature,
                keyring=TEST_KEYRING,
            )

        with self.assertRaisesRegexp(signet.GPGInvalidSignatureError, 'Key mismatch: got \w+; expected \w+'):
            signet.gpg_verify(
                'wrongkeyid',
                TEST_DATA,
                signature,
                keyring=TEST_KEYRING,
            )

        with self.assertRaisesRegexp(signet.GPGKeyNotFoundError, 'Unknown key'):
            signet.gpg_verify(
                TEST_KEYID,
                TEST_DATA,
                signature,
                keyring=fixtures.path('empty'),
            )
