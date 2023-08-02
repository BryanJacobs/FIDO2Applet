from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from fido2.cose import ES256

from .ctap_test import BasicAttestationTestCase


class CTAPBasicAttestationTestCase(BasicAttestationTestCase):

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params)
        self.install_attestation_cert()

    def test_aaguid_visible_in_info(self):
        info = self.ctap2.get_info()
        self.assertEqual(self.aaguid, info.aaguid)

    def test_cert_attestation(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual("packed", cred_res.fmt)
        self.assertIsNotNone(cred_res.att_stmt)
        self.assertEqual(self.aaguid, cred_res.auth_data.credential_data.aaguid)
        x5c = cred_res.att_stmt['x5c']
        self.assertEqual(2, len(x5c))
        auth_cert, ca_cert = x5c
        self.assertEqual(self.cert, auth_cert)
        self.assertEqual(ES256.ALGORITHM, cred_res.att_stmt['alg'])
        sig = cred_res.att_stmt.get('sig')
        self.assertIsNotNone(sig)

        cred_pubkey = cred_res.auth_data.credential_data.public_key
        with self.assertRaises(InvalidSignature):
            cred_pubkey.verify(cred_res.auth_data + self.client_data, sig)
        self.public_key.verify(sig,
                               cred_res.auth_data + self.client_data,
                               ECDSA(SHA256()))
        auth_cert_der = x509.load_der_x509_certificate(x5c[0])
        ca_cert_der = x509.load_der_x509_certificate(x5c[1])
        auth_cert_der.verify_directly_issued_by(ca_cert_der)
        ca_cert_der.verify_directly_issued_by(ca_cert_der)
        self.assertEqual(self.public_key, auth_cert_der.public_key())
        self.assertEqual(self.ca_public_key, ca_cert_der.public_key())

        assert_client_data = self.get_random_client_data()

        assert_res = self.get_assertion_from_cred(cred_res, client_data=assert_client_data)
        self.assertIsNone(assert_res.number_of_credentials)
        self.assertIsNone(assert_res.user)
        self.assertEqual(cred_res.auth_data.credential_data.credential_id,
                         assert_res.credential['id'])

        cred_res.auth_data.credential_data.public_key.verify(
            assert_res.auth_data + assert_client_data, assert_res.signature
        )

        with self.assertRaises(InvalidSignature):
            self.public_key.verify(assert_res.signature,
                                   assert_res.auth_data + assert_client_data,
                                   ECDSA(SHA256()))
        with self.assertRaises(InvalidSignature):
            self.ca_public_key.verify(assert_res.signature,
                                      assert_res.auth_data + assert_client_data,
                                      ECDSA(SHA256()))
