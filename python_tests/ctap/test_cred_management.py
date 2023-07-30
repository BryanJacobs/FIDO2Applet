import secrets
from typing import Optional

from cryptography.hazmat.primitives import hashes
from fido2.client import _Ctap2ClientBackend
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, PinProtocolV2
from fido2.webauthn import ResidentKeyRequirement
import fido2.features

from .ctap_test import CTAPTestCase, FixedPinUserInteraction

try:
    fido2.features.webauthn_json_mapping.enabled = False
except:
    pass


class CredManagementTestCase(CTAPTestCase):

    PERMISSION_CRED_MGMT = 4
    pin: str

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params)

        self.pin = secrets.token_hex(10)
        ClientPin(self.ctap2).set_pin(self.pin)

    def get_credential_management(self, permissions: Optional[int] = None) -> CredentialManagement:
        if permissions is None:
            permissions = self.PERMISSION_CRED_MGMT

        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin),
        )
        # noinspection PyTypeChecker
        be: _Ctap2ClientBackend = client._backend
        token = be._get_token(ClientPin(self.ctap2), permissions=permissions,
                              rp_id=None, event=None, on_keepalive=None, allow_internal_uv=False)
        return CredentialManagement(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=token)

    def test_cannot_enumerate_without_permission(self):
        cm = self.get_credential_management(permissions=0)

        with self.assertRaises(CtapError) as e:
            cm.enumerate_rps()

        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.exception.code)

    def _rp_id_hash(self, rp_id: str) -> bytes:
        digester = hashes.Hash(hashes.SHA256())
        digester.update(rp_id.encode())
        return digester.finalize()

    def test_cred_overwrites(self):
        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin)
        )

        for i in range(3):
            client.make_credential(options=self.get_high_level_make_cred_options(
                resident_key=ResidentKeyRequirement.REQUIRED
            ))

        cm = self.get_credential_management()
        rp_res = cm.enumerate_rps()
        self.assertEqual(1, len(rp_res))

        cred_res = cm.enumerate_creds(self._rp_id_hash(self.rp_id))
        self.assertEqual(1, len(cred_res))

    def test_cred_management(self):
        rp_ids = []
        creds_by_rp = {}

        for rp_num in range(3):
            rp_id = f'rp_{secrets.token_hex(3)}_no{rp_num}'
            origin = f'https://{rp_id}'
            client = self.get_high_level_client(
                user_interaction=FixedPinUserInteraction(self.pin),
                origin=origin
            )

            rp_ids.append(rp_id)
            creds_by_rp[rp_id] = []
            for cred_num in range(5):
                user = secrets.token_bytes(20)
                res = client.make_credential(options=self.get_high_level_make_cred_options(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    rp_id=rp_id,
                    user_id=user
                ))
                creds_by_rp[rp_id].append(res.attestation_object.auth_data.credential_data.credential_id)

        cm = self.get_credential_management()
        rp_res = cm.enumerate_rps()
        gotten_rpids = [x[3]['id'] for x in rp_res]
        self.assertEqual(rp_ids, gotten_rpids)

        for rp in rp_ids:
            rp_id_hash = self._rp_id_hash(rp)
            cred_res = cm.enumerate_creds(rp_id_hash)
            creds = [x[7]['id'] for x in cred_res]
            self.assertEqual(sorted(creds_by_rp[rp]), sorted(creds))
