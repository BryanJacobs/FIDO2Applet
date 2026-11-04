import secrets
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin

from .ctap_test import CTAPTestCase


class HighSecurityRKTestCase(CTAPTestCase):
    """
    Installed with both low-security options off, so discoverable credentials use the wrapping key
    that is only available once the PIN has been used.
    """

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes([0xA2, 0x01, 0xF4, 0x03, 0xF4]))
        self.pin = secrets.token_hex(8)
        self.client_pin = ClientPin(self.ctap2)
        self.client_pin.set_pin(self.pin)

    def make_rk(self) -> bytes:
        protocol = self.client_pin.protocol
        token = self.client_pin.get_pin_token(self.pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, self.rp_id)
        cred = self.ctap2.make_credential(**self.basic_makecred_params, options={"rk": True},
                                          pin_uv_param=protocol.authenticate(token, self.client_data),
                                          pin_uv_protocol=protocol.VERSION)
        return cred.auth_data.credential_data.credential_id

    def assert_locked(self, allow_list) -> None:
        with self.assertRaises(CtapError) as e:
            self.ctap2.get_assertion(self.rp_id, self.client_data, allow_list)
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)

    def test_rk_creation_requires_pin(self):
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params, options={"rk": True})
        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    def test_locked_lookup_by_id_finds_nothing(self):
        cred_id = self.make_rk()
        self.softResetCard()
        self.assert_locked([{"type": "public-key", "id": cred_id}])

    def test_locked_discovery_finds_nothing(self):
        self.make_rk()
        self.softResetCard()
        self.assert_locked(None)

    def test_usable_without_pin_after_pin_was_used(self):
        cred_id = self.make_rk()
        self.softResetCard()
        self.client_pin.get_pin_token(self.pin, ClientPin.PERMISSION.GET_ASSERTION, self.rp_id)
        assertion = self.ctap2.get_assertion(self.rp_id, self.client_data, [{"type": "public-key", "id": cred_id}])
        self.assertEqual(cred_id, assertion.credential["id"])
