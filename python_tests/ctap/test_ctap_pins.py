import secrets
from typing import Optional

from fido2.client import ClientError, PinRequiredError
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from parameterized import parameterized

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class CTAPPINTestCase(CTAPTestCase):

    cp: ClientPin

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params=install_params)
        self.reset()

    def reset(self):
        super().reset()
        self.cp = ClientPin(self.ctap2)

    def test_pin_change(self):
        first_pin = secrets.token_hex(16)
        second_pin = secrets.token_hex(16)
        old_pin_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(first_pin))
        new_pin_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(second_pin))

        info_before_switch = self.ctap2.get_info()
        self.cp.set_pin(first_pin)
        info_after_switch = self.ctap2.get_info()
        self.cp.change_pin(first_pin, second_pin)
        with self.assertRaises(ClientError) as e:
            # Old PIN is now wrong
            old_pin_client.make_credential(self.get_high_level_make_cred_options())

        # New PIN is correct
        new_pin_client.make_credential(self.get_high_level_make_cred_options())

        self.assertFalse(info_before_switch.options['clientPin'])
        self.assertTrue(info_after_switch.options['clientPin'])
        self.assertEqual([1, 2], info_before_switch.pin_uv_protocols)
        self.assertEqual([1, 2], info_after_switch.pin_uv_protocols)

    def test_pin_cleared_by_reset(self):
        first_pin = secrets.token_hex(16)

        self.cp.set_pin(first_pin)
        self.reset()
        info_after_reset = self.ctap2.get_info()
        with self.assertRaises(CtapError) as e:
            self.cp.change_pin(old_pin=first_pin, new_pin=secrets.token_hex(10))

        self.assertFalse(info_after_reset.options['clientPin'])
        self.assertEqual(CtapError.ERR.PIN_NOT_SET, e.exception.code)

    def test_cannot_set_pin_twice(self):
        first_pin = secrets.token_hex(16)
        self.cp.set_pin(first_pin)

        with self.assertRaises(CtapError) as e:
            self.cp.set_pin(first_pin)

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    def test_pin_change_providing_incorrect_old_pin(self):
        first_pin = secrets.token_hex(16)
        second_pin = secrets.token_hex(16)
        self.cp.set_pin(first_pin)

        with self.assertRaises(CtapError) as e:
            self.cp.change_pin("12345", second_pin)

        self.assertEqual(CtapError.ERR.PIN_INVALID, e.exception.code)

    @parameterized.expand([
        ("short", 1, False),
        ("minimal", 2, True),
        ("reasonable", 8, True),
        ("maximal", 31, True),
        ("overlong", 32, False),
        ("huge", 40, False),
    ])
    def test_pin_lengths(self, _, length, valid):
        pin = secrets.token_hex(length)

        def do_client_pin():
            pin_as_bytes = pin.encode()
            while len(pin_as_bytes) < 64:
                pin_as_bytes += b'\0'

            ka, ss = self.cp._get_shared_secret()
            enc = self.cp.protocol.encrypt(ss, pin_as_bytes)
            puv = self.cp.protocol.authenticate(ss, enc)
            self.ctap2.client_pin(
                2,
                ClientPin.CMD.SET_PIN,
                key_agreement=ka,
                new_pin_enc=enc,
                pin_uv_param=puv
            )

        if valid:
            do_client_pin()
        else:
            with self.assertRaises(CtapError) as e:
                do_client_pin()

            self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_pin_set_and_not_provided_library_level(self):
        pin = secrets.token_hex(30)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client()

        with self.assertRaises(PinRequiredError):
            client.make_credential(options=self.get_high_level_make_cred_options())

    def test_pin_set_and_not_provided_underyling_impl(self):
        pin = secrets.token_hex(30)
        ClientPin(self.ctap2).set_pin(pin)

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

