import secrets
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec

from fido2.ctap2.base import args

from ctap.ctap_test import BasicAttestationTestCase


class AttestationModeSwitchWithFixedKeyTestCase(BasicAttestationTestCase):
    def setUp(self, install_params: Optional[bytes] = None) -> None:

        privkey = ec.generate_private_key(ec.SECP256R1())
        self.public_key = privkey.public_key()
        private_bytes = privkey.private_numbers().private_value.to_bytes(length=32, byteorder='big')

        super().setUp(bytes([0xA2, 0x00, 0xF5, 0x0F, 0x58, 0x20]) + private_bytes)

    def test_u2f_supported_after_switch(self):
        info_before = self.ctap2.get_info()

        cert_bytes = secrets.token_bytes(100)
        cert = self.gen_attestation_cert(cert_bytes=[cert_bytes], public_key=self.public_key)
        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

        info_after = self.ctap2.get_info()
        self.assertFalse("U2F_V2" in info_before.versions)
        self.assertTrue("U2F_V2" in info_after.versions)
