import secrets
from typing import Optional

from fido2.ctap2.base import args
from fido2.webauthn import Aaguid
from parameterized import parameterized

from ctap.ctap_test import BasicAttestationTestCase


class AttestationModeSwitchTestCase(BasicAttestationTestCase):
    VENDOR_COMMAND_SWITCH_ATT = 0x46

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes([0x01]))

    @parameterized.expand([
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
        cert = self.gen_attestation_cert(cert_bytes)

        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        info_after = self.ctap2.get_info()
        self.assertEqual(self.aaguid, info_after.aaguid)

        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(self.cert, cred_res.att_stmt['x5c'][0])

