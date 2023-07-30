import secrets
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2.base import args
from fido2.webauthn import Aaguid

from ctap.ctap_test import CTAPTestCase


class LockedSelfAttestationTestCase(CTAPTestCase):
    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes())

    def test_switching_attestation_modes_disallowed(self):
        info = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info.aaguid)
        with self.assertRaises(CtapError) as e:
            self.ctap2.send_cbor(
                0x46,
                args(secrets.token_bytes(122))
            )
        self.assertEqual(CtapError.ERR.NOT_ALLOWED, e.exception.code)

