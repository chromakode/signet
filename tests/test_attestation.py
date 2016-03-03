import copy
import hashlib
import unittest

import signet
from tests import (
    TEST_KEYID,
    TEST_KEYRING,
    TEST_SECRET_KEYRING,
)


class TestAttestation(unittest.TestCase):
    def test_make_attestation_and_verify(self):
        identifier = 'sha256:' + hashlib.sha256('hello, world'.encode('ascii')).hexdigest()
        attestation_data = {
            'id': identifier,
            'comment': 'test!'
        }
        attestation = signet.make_attestation(attestation_data, TEST_KEYID, TEST_KEYRING, TEST_SECRET_KEYRING)
        signet.verify_attestation(attestation, TEST_KEYRING)

        with self.assertRaisesRegexp(signet.GPGInvalidSignatureError, 'Invalid signature'):
            bad_sig_attestation = copy.deepcopy(attestation)
            bad_sig_attestation["data"]["tampered"] = True
            signet.verify_attestation(bad_sig_attestation, TEST_KEYRING)

        with self.assertRaisesRegexp(signet.GPGInvalidSignatureError, 'Key mismatch: got \w+; expected \w+'):
            bad_key_attestation = copy.deepcopy(attestation)
            bad_key_attestation["key"] = "wrong"
            signet.verify_attestation(bad_key_attestation, TEST_KEYRING)
