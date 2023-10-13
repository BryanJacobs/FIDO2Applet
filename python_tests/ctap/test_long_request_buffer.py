import secrets
import random

from typing import Optional

from .ctap_test import CTAPTestCase


class CTAPLongRequestBufferTestCase(CTAPTestCase):

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(bytes([0xA1, 0x0A, 0x19, 0x08, 0x00]))

    def test_info_shows_long_message_size(self):
        info = self.ctap2.get_info()
        self.assertEqual(2048, info.max_msg_size)

    def test_long_request_handled(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        allow_list = []
        total_len = 0
        while total_len < 1100:
            cred_len = random.randint(1, 112)
            rando_data = secrets.token_bytes(cred_len)
            allow_list.append({
                "type": "public-key",
                "id": rando_data
            })
            total_len += cred_len + 20
        allow_list.append({
            "type": "public-key",
            "id": cred.auth_data.credential_data.credential_id
        })
        self.ctap2.get_assertion(
            rp_id=self.rp_id,
            client_data_hash=self.client_data,
            allow_list=allow_list
        )
