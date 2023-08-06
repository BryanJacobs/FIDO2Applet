import secrets
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2 import Config, ClientPin, PinProtocolV2
from fido2.ctap2.extensions import MinPinLengthExtension
from parameterized import parameterized

from .ctap_test import CTAPTestCase


class SetMinPinTestCase(CTAPTestCase):

    cp: ClientPin
    pin: Optional[str] = None

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params=install_params)
        self.cp = ClientPin(self.ctap2)

    def get_cfg(self) -> Config:
        if self.pin is None:
            return Config(self.ctap2)
        uv = self.cp.get_pin_token(self.pin,
                                   permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        return Config(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)

    def test_info_min_pin_length(self):
        info = self.ctap2.get_info()
        self.assertEqual(4, info.min_pin_length)

    def test_info_max_rps_for_setminpin(self):
        info = self.ctap2.get_info()
        self.assertEqual(0, info.max_rpids_for_min_pin)

    def test_setminpin_option(self):
        info = self.ctap2.get_info()
        self.assertEqual(True, info.options.get("setMinPINLength"))

    @parameterized.expand([
        ("authenticated", True),
        ("unauthenticated", False),
    ])
    def test_setminpin_visible_in_info(self, _, setpin: bool):
        if setpin:
            self.pin = secrets.token_hex(10)
            self.cp.set_pin(self.pin)

        self.get_cfg().set_min_pin_length(min_pin_length=8)

        info = self.ctap2.get_info()
        self.assertEqual(8, info.min_pin_length)

    def test_setminpin_requires_pin_when_set(self):
        self.pin = secrets.token_hex(10)
        self.cp.set_pin(self.pin)

        with self.assertRaises(CtapError) as e:
            Config(self.ctap2).set_min_pin_length(min_pin_length=2)

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    @parameterized.expand([
        (4, 3),
        (8, 7),
        (30, 4),
    ])
    def test_setminpin_cannot_go_down(self, original_value, new_value):
        self.get_cfg().set_min_pin_length(min_pin_length=original_value)

        with self.assertRaises(CtapError) as e:
            self.get_cfg().set_min_pin_length(min_pin_length=new_value)

        self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_setminpin_overlong(self):
        with self.assertRaises(CtapError) as e:
            self.get_cfg().set_min_pin_length(min_pin_length=70)

        self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_four_ascii_chars(self):
        self.cp.set_pin("aaaa")

    def test_four_ascii_chars_rejected_when_length_increased(self):
        self.get_cfg().set_min_pin_length(min_pin_length=5)

        with self.assertRaises(CtapError) as e:
            self.cp.set_pin("aaaa")

        self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_four_multibyte_chars_rejected_when_length_increased(self):
        self.get_cfg().set_min_pin_length(min_pin_length=5)

        with self.assertRaises(CtapError) as e:
            self.cp.set_pin("✈✈✈✈")

        self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_five_multibyte_chars_accepted_when_length_increased(self):
        self.get_cfg().set_min_pin_length(min_pin_length=5)

        self.cp.set_pin("✈✈ä✈✈")

    def test_four_multibyte_chars_accepted_normally(self):
        self.cp.set_pin("✈✈✈✈")

    def test_change_without_pin_does_not_force_change(self):
        self.get_cfg().set_min_pin_length(min_pin_length=10)
        info = self.ctap2.get_info()

        self.assertEqual(False, info.force_pin_change)

    def test_change_with_pin_does_force_change(self):
        self.pin = secrets.token_hex(10)
        self.cp.set_pin(self.pin)

        self.get_cfg().set_min_pin_length(min_pin_length=10)
        info = self.ctap2.get_info()

        self.assertEqual(True, info.force_pin_change)
        self.assertEqual(10, info.min_pin_length)

    def test_change_with_pin_to_same_length_does_not_force_change(self):
        self.pin = secrets.token_hex(10)
        self.cp.set_pin(self.pin)

        self.get_cfg().set_min_pin_length(min_pin_length=4)
        info = self.ctap2.get_info()

        self.assertEqual(False, info.force_pin_change)

    def test_cannot_get_uv_when_change_forced(self):
        self.pin = secrets.token_hex(10)
        self.cp.set_pin(self.pin)
        self.get_cfg().set_min_pin_length(force_change_pin=True)

        with self.assertRaises(CtapError) as e:
            self.cp.get_pin_token(self.pin)

        self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_cannot_force_change_without_pin(self):
        with self.assertRaises(CtapError) as e:
            self.get_cfg().set_min_pin_length(force_change_pin=True)

        self.assertEqual(CtapError.ERR.PIN_NOT_SET, e.exception.code)

    def test_accepts_extension_on_makecred(self):
        client = self.get_high_level_client([MinPinLengthExtension])
        client.make_credential(self.get_high_level_make_cred_options(extensions={
            "minPinLength": True
        }))

    def test_rejects_false_extension_on_makecred(self):
        self.basic_makecred_params['extensions'] = {
            'minPinLength': False
        }

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.INVALID_OPTION, e.exception.code)
