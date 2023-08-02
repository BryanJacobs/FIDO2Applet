import secrets
from typing import Optional

from fido2.ctap1 import ApduError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement

from .ctap_test import BasicAttestationTestCase, FixedPinUserInteraction


class U2FTestCase(BasicAttestationTestCase):

    rp_hash: bytes

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params)
        self.install_attestation_cert()
        self.rp_hash = self.rp_id_hash(self.rp_id)

    def test_u2f_version(self):
        res = self.ctap1.get_version()
        self.assertEqual("U2F_V2", res)

    def test_u2f_register(self):
        res = self.ctap1.register(self.client_data, self.rp_hash)
        self.assertEqual(self.cert, res.certificate)
        res.verify(app_param=self.rp_hash, client_param=self.client_data)

    def test_u2f_authenticate(self):
        cred = self.ctap1.register(self.client_data, self.rp_hash)

        res = self.ctap1.authenticate(client_param=self.client_data,
                                      app_param=self.rp_hash,
                                      key_handle=cred.key_handle)
        res.verify(app_param=self.rp_hash, client_param=self.client_data,
                   public_key=cred.public_key)

    def test_u2f_authenticate_rejects_mismatching_rpid(self):
        cred = self.ctap1.register(self.client_data, self.rp_hash)

        with self.assertRaises(ApduError) as e:
            res = self.ctap1.authenticate(client_param=self.client_data,
                                          app_param=secrets.token_bytes(32),
                                          key_handle=cred.key_handle)
        self.assertEqual(27264, e.exception.code)

    def test_authenticate_increases_counter(self):
        cred = self.ctap1.register(self.client_data, self.rp_hash)

        res_1 = self.ctap1.authenticate(client_param=self.client_data,
                                        app_param=self.rp_hash,
                                        key_handle=cred.key_handle)
        res_2 = self.ctap1.authenticate(client_param=self.client_data,
                                        app_param=self.rp_hash,
                                        key_handle=cred.key_handle)
        self.assertEqual(res_1.counter + 1, res_2.counter)

    def test_u2f_credential_usable_over_ctap2(self):
        res = self.ctap1.register(self.client_data, self.rp_hash)
        self.ctap2.get_assertion(rp_id=self.rp_id,
                                 allow_list=[
                                     {
                                         "type": "public-key",
                                         "id": res.key_handle
                                     }
                                 ],
                                 client_data_hash=secrets.token_bytes(32))

    def test_ctap2_credential_usable_over_u2f(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        res = self.ctap1.authenticate(client_param=secrets.token_bytes(32),
                                      app_param=self.rp_hash,
                                      key_handle=cred.auth_data.credential_data.credential_id)

    def test_cred_protect_low_usable_over_u2f(self):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            extensions={
                "credentialProtectionPolicy": CredProtectExtension.POLICY.OPTIONAL_WITH_LIST
            }
        ))
        self.ctap1.authenticate(client_param=secrets.token_bytes(32),
                                app_param=self.rp_hash,
                                key_handle=cred.attestation_object.auth_data.credential_data.credential_id)

    def test_cred_protect_high_not_usable_over_u2f(self):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            extensions={
                "credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED
            }
        ))
        with self.assertRaises(ApduError) as e:
            self.ctap1.authenticate(client_param=secrets.token_bytes(32),
                                    app_param=self.rp_hash,
                                    key_handle=cred.attestation_object.auth_data.credential_data.credential_id)
        self.assertEqual(27264, e.exception.code)

    def test_discoverable_not_usable_over_u2f(self):
        client = self.get_high_level_client()
        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))
        with self.assertRaises(ApduError) as e:
            self.ctap1.authenticate(client_param=secrets.token_bytes(32),
                                    app_param=self.rp_hash,
                                    key_handle=cred.attestation_object.auth_data.credential_data.credential_id)
        self.assertEqual(27264, e.exception.code)

    def test_discoverable_not_usable_over_u2f_with_pin(self):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))
        with self.assertRaises(ApduError) as e:
            self.ctap1.authenticate(client_param=secrets.token_bytes(32),
                                    app_param=self.rp_hash,
                                    key_handle=cred.attestation_object.auth_data.credential_data.credential_id)
        self.assertEqual(27264, e.exception.code)
