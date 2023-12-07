import secrets
from typing import Optional

from fido2.ctap2.base import args
from parameterized import parameterized

from ctap.ctap_test import BasicAttestationTestCase


class ExtendedAPDUTestCase(BasicAttestationTestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.USE_EXT_APDU = True
        super().setUpClass()

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes([0xA1, 0x00, 0xF5]))

    def test_get_info(self):
        info = self.ctap2.get_info()
        self.assertEqual(bytes([0] * 16), info.aaguid)

    def test_makecred(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertTrue(res.auth_data.counter < 16)
        self.assertTrue(res.auth_data.counter > 0)

    def test_extreme_makecred_input(self):
        self.basic_makecred_params['user'] = {
            'id': secrets.token_bytes(32),
            'name': secrets.token_hex(10),
            'display_name': secrets.token_hex(100),
            'icon': secrets.token_hex(120)
        }
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_chained_assertions(self):
        self.basic_makecred_params['options'] = {'rk': True}
        num_creds = 5

        users = set()

        for x in range(num_creds):
            user = secrets.token_bytes(32)
            users.add(user)
            self.basic_makecred_params['user']['id'] = user
            self.ctap2.make_credential(**self.basic_makecred_params)

        asserts = self.get_assertion(rp_id=self.rp_id)
        self.assertEqual(num_creds, asserts.number_of_credentials)

        next_cred = self.ctap2.get_next_assertion()
        self.assertTrue(next_cred.user.get('id') in users)

    @parameterized.expand([
        ("short", 100),
        ("medium", 220),
        ("long", 900),
        ("xlong", 5000)
    ])
    def test_basic_auth(self, _, length):
        cert_bytes = secrets.token_bytes(length)
        cert = self.gen_attestation_cert([cert_bytes])
        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(cert_bytes, cred.att_stmt.get("x5c")[0])
