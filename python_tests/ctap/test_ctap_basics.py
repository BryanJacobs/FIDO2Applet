import fido2.features
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.webauthn import Aaguid

from .ctap_test import CTAPTestCase

try:
    fido2.features.webauthn_json_mapping.enabled = False
except:
    pass


class CTAPBasicsTestCase(CTAPTestCase):
    def test_info_supported_versions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["FIDO_2_0", "FIDO_2_1"], info.versions)

    def test_info_supported_extensions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["credProtect", "hmac-secret"], info.extensions)

    def test_info_aaguid_none(self):
        info = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info.aaguid)

    def test_make_credential_self_attestation(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertIsNone(res.ep_att)
        self.assertIsNone(res.auth_data.extensions)
        self.assertIsNotNone(res.att_stmt)
        self.assertIsNone(res.att_stmt.get('x5c'))
        self.assertIsNone(res.large_blob_key)
        self.assertEqual(res.auth_data.FLAG.UP | res.auth_data.FLAG.ATTESTED, res.auth_data.flags)

        self.assertEqual(ES256.ALGORITHM, res.att_stmt['alg'])
        self.assertIsNotNone(res.att_stmt['sig'])
        self.assertEqual(Aaguid.NONE, res.auth_data.credential_data.aaguid)

        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual(64, len(res.auth_data.credential_data.credential_id))

    def test_counter_increases_on_makecred(self):
        cred_res_1 = self.ctap2.make_credential(**self.basic_makecred_params)
        cred_res_2 = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(cred_res_2.auth_data.counter, cred_res_1.auth_data.counter + 1)

    def test_counter_increases_on_assert(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res_1 = self.get_assertion_from_cred(cred_res, client_data=self.get_random_client_data())
        assert_res_2 = self.get_assertion_from_cred(cred_res, client_data=self.get_random_client_data())
        self.assertEqual(assert_res_1.auth_data.counter, cred_res.auth_data.counter + 1)
        self.assertEqual(assert_res_2.auth_data.counter, assert_res_1.auth_data.counter + 1)

    def test_basic_assertion(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        assert_client_data = self.get_random_client_data()

        assert_res = self.get_assertion_from_cred(cred_res, client_data=assert_client_data)
        self.assertIsNone(assert_res.number_of_credentials)
        self.assertIsNone(assert_res.user)
        self.assertEqual(cred_res.auth_data.credential_data.credential_id,
                         assert_res.credential['id'])
        cred_res.auth_data.credential_data.public_key.verify(
            assert_res.auth_data + assert_client_data, assert_res.signature
        )

    def test_no_keys_found(self):
        self.ctap2.make_credential(**self.basic_makecred_params)

        assert_client_data = self.get_random_client_data()

        with self.assertRaises(CtapError) as e:
            self.ctap2.get_assertion(
                rp_id=self.basic_makecred_params['rp']['id'],
                client_data_hash=assert_client_data,
                allow_list=[]
            )
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)

    def test_non_matching_rp(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        assert_client_data = self.get_random_client_data()

        with self.assertRaises(CtapError) as e:
            self.ctap2.get_assertion(
                rp_id='___different',
                client_data_hash=assert_client_data,
                allow_list=[
                    {
                        "type": "public-key",
                        "id": cred_res.auth_data.credential_data.credential_id
                    }
                ]
            )
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)

    def test_make_credential_with_bogus_extension(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params,
                                         extensions={
                                             "bogosity": True
                                         })

        self.assertEqual(None, res.auth_data.extensions)
