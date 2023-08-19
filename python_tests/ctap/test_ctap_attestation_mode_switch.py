import secrets
from typing import Optional

from fido2.ctap2.base import args
from fido2.webauthn import Aaguid
from parameterized import parameterized

from ctap.ctap_test import BasicAttestationTestCase


class AttestationModeSwitchTestCase(BasicAttestationTestCase):
    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes([0xA1, 0x00, 0xF5]))

    @parameterized.expand([
        ("tiny", 3),
        ("very short", 140),
        ("short", 300),
        ("medium", 900),
        ("long", 2000),
        ("very long", 8000),
    ])
    def test_applying_cert_len(self, _, length):
        info_before = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info_before.aaguid)

        cert_bytes = secrets.token_bytes(length)
        cert = self.gen_attestation_cert([cert_bytes])

        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        info_after = self.ctap2.get_info()
        self.assertEqual(self.aaguid, info_after.aaguid)

        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(self.cert, cred_res.att_stmt['x5c'][0])
        self.assertIsNone(cred_res.large_blob_key)

    @parameterized.expand([
        ("tiny", 3),
        ("very short", 140),
        ("short", 300),
        ("medium", 900),
        ("long", 2000),
        ("very long", 8000),
    ])
    def test_applying_cert_len_with_large_blob(self, _, length):
        info_before = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info_before.aaguid)

        cert_bytes = secrets.token_bytes(length)
        cert = self.gen_attestation_cert([cert_bytes])

        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        info_after = self.ctap2.get_info()
        self.assertEqual(self.aaguid, info_after.aaguid)

        self.basic_makecred_params['options'] = {'rk': True}
        self.basic_makecred_params['extensions'] = {'largeBlobKey': True}
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(self.cert, cred_res.att_stmt['x5c'][0])
        self.assertIsNotNone(cred_res.large_blob_key)
        self.assertEqual(32, len(cred_res.large_blob_key))

    def test_u2f_supported_after_switch(self):
        info_before = self.ctap2.get_info()

        cert_bytes = secrets.token_bytes(100)
        cert = self.gen_attestation_cert([cert_bytes])
        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        info_after = self.ctap2.get_info()
        self.assertFalse("U2F_V2" in info_before.versions)
        self.assertTrue("U2F_V2" in info_after.versions)

    def test_switching_survives_soft_reset(self):
        cert_bytes = secrets.token_bytes(100)
        cert = self.gen_attestation_cert([cert_bytes])
        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        self.softResetCard()

        info = self.ctap2.get_info()
        self.assertTrue("U2F_V2" in info.versions)
