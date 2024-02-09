import secrets
import unittest
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, PinProtocolV2

from .ctap_test import CTAPTestCase


class AuthenticatorConfigTestCase(CTAPTestCase):

    cp: ClientPin

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params=install_params)
        self.reset()

    def reset(self):
        super().reset()
        self.cp = ClientPin(self.ctap2)

    def test_alwaysUv_default_off(self):
        info = self.ctap2.get_info()
        self.assertFalse(info.options.get("alwaysUv"))
        self.assertFalse("U2F_V2" in info.versions)

    def test_alwaysUv_off_after_pin_set(self):
        self.cp.set_pin(secrets.token_hex(10))

        info = self.ctap2.get_info()
        self.assertFalse(info.options.get("alwaysUv"))
        self.assertFalse("U2F_V2" in info.versions)

    def test_enable_alwaysUv(self):
        Config(self.ctap2).toggle_always_uv()

        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("alwaysUv"))
        self.assertFalse(info.options.get("makeCredUvNotRequired"))
        self.assertFalse("U2F_V2" in info.versions)

    @unittest.skip("EP is disabled out of the box")
    def test_enable_enterprise_attestation(self):
        Config(self.ctap2).enable_enterprise_attestation()

        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("ep"))

    def test_enterprise_attestation_accepted_when_enabled(self):
        Config(self.ctap2).enable_enterprise_attestation()

        self.basic_makecred_params["enterprise_attestation"] = 1

        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_enterprise_attestation_rejects_invalid_value_when_enabled(self):
        Config(self.ctap2).enable_enterprise_attestation()

        self.basic_makecred_params["enterprise_attestation"] = 9
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.INVALID_OPTION, e.exception.code)

    def test_enterprise_attestation_rejected_when_disabled(self):
        self.basic_makecred_params["enterprise_attestation"] = 9

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.INVALID_PARAMETER, e.exception.code)

    def test_makecred_rejected_with_alwaysUv_no_pin(self):
        Config(self.ctap2).toggle_always_uv()

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.PIN_NOT_SET, e.exception.code)

    def test_disable_alwaysUv_without_pin_rejected(self):
        Config(self.ctap2).toggle_always_uv()

        with self.assertRaises(CtapError) as e:
            Config(self.ctap2).toggle_always_uv()

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    def test_toggling_alwaysUv_survives_soft_reset(self):
        Config(self.ctap2).toggle_always_uv()

        self.softResetCard()

        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("alwaysUv"))

    def test_toggle_alwaysUv_without_acfg_perm(self):
        pin = secrets.token_hex(10)
        Config(self.ctap2).toggle_always_uv()
        self.cp.set_pin(pin)
        uv = self.cp.get_pin_token(pin)
        cfg = Config(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)

        with self.assertRaises(CtapError) as e:
            cfg.toggle_always_uv()

        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.exception.code)

    def test_toggle_alwaysUv_with_pin(self):
        pin = secrets.token_hex(10)
        Config(self.ctap2).toggle_always_uv()
        self.cp.set_pin(pin)
        uv = self.cp.get_pin_token(pin,
                                   permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        cfg = Config(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)
        cfg.toggle_always_uv()

        self.test_alwaysUv_default_off()
