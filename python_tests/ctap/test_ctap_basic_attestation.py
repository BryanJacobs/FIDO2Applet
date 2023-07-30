from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from fido2.cose import ES256

from .ctap_test import BasicAttestationTestCase


class CTAPBasicAttestationTestCase(BasicAttestationTestCase):

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        if install_params is None:
            install_params = self.gen_attestation_cert()
        super().setUp(install_params)

    def test_aaguid_visible_in_info(self):
        info = self.ctap2.get_info()
        self.assertEqual(self.aaguid, info.aaguid)

    def test_cert_attestation(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual("packed", cred_res.fmt)
        self.assertIsNotNone(cred_res.att_stmt)
        self.assertEqual(self.aaguid, cred_res.auth_data.credential_data.aaguid)
        self.assertEqual(self.cert, cred_res.att_stmt['x5c'][0])
        self.assertEqual(ES256.ALGORITHM, cred_res.att_stmt['alg'])
        sig = cred_res.att_stmt.get('sig')
        self.assertIsNotNone(sig)

        cred_pubkey = cred_res.auth_data.credential_data.public_key
        with self.assertRaises(InvalidSignature):
            cred_pubkey.verify(cred_res.auth_data + self.client_data, sig)
        self.public_key.verify(sig,
                               cred_res.auth_data + self.client_data,
                               ECDSA(SHA256()))

        assert_client_data = self.get_random_client_data()

        assert_res = self.get_assertion_from_cred(cred_res, client_data=assert_client_data)
        self.assertIsNone(assert_res.number_of_credentials)
        self.assertIsNone(assert_res.user)
        self.assertEqual(cred_res.auth_data.credential_data.credential_id,
                         assert_res.credential['id'])

        with self.assertRaises(InvalidSignature):
            cred_res.auth_data.credential_data.public_key.verify(
                assert_res.auth_data + assert_client_data, assert_res.signature
            )

        self.public_key.verify(assert_res.signature,
                               assert_res.auth_data + assert_client_data,
                               ECDSA(SHA256()))
