import copy
import secrets

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.webauthn import Aaguid

from .ctap_test import CTAPTestCase


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
        rp_id = secrets.token_hex(50)
        self.basic_makecred_params['rp']['id'] = rp_id
        res = self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertIsNone(res.ep_att)
        self.assertIsNone(res.auth_data.extensions)
        self.assertIsNotNone(res.att_stmt)
        self.assertIsNone(res.att_stmt.get('x5c'))
        self.assertIsNone(res.large_blob_key)
        self.assertEqual(res.auth_data.FLAG.UP | res.auth_data.FLAG.ATTESTED, res.auth_data.flags)
        self.assertEqual(self.rp_id_hash(rp_id), res.auth_data.rp_id_hash)

        self.assertEqual(ES256.ALGORITHM, res.att_stmt['alg'])
        self.assertIsNotNone(res.att_stmt['sig'])
        self.assertEqual(Aaguid.NONE, res.auth_data.credential_data.aaguid)

        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual(64, len(res.auth_data.credential_data.credential_id))

    def test_make_credential_rejects_up_false(self):
        self.basic_makecred_params['options'] = {
            'up': False
        }

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.INVALID_OPTION, e.exception.code)

    def test_make_credential_accepts_empty_pin_auth(self):
        self.basic_makecred_params['pin_uv_param'] = b""
        self.basic_makecred_params['pin_uv_protocol'] = 1

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.PIN_NOT_SET, e.exception.code)

    def test_empty_pin_auth_rejected_when_real_pin_set(self):
        pin = secrets.token_hex(5)
        ClientPin(self.ctap2).set_pin(pin)
        self.basic_makecred_params['pin_uv_param'] = b""
        self.basic_makecred_params['pin_uv_protocol'] = 1

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.PIN_INVALID, e.exception.code)

    def test_get_assertion_accepts_empty_pin_auth(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        with self.assertRaises(CtapError) as e:
            self.get_assertion_from_cred(cred,
                                         pin_uv_param=b"",
                                         pin_uv_protocol=1)
        self.assertEqual(CtapError.ERR.PIN_NOT_SET, e.exception.code)

    def test_assertion_empty_pin_auth_rejected_when_pin_set(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        pin = secrets.token_hex(5)
        ClientPin(self.ctap2).set_pin(pin)
        with self.assertRaises(CtapError) as e:
            self.get_assertion_from_cred(cred,
                                         pin_uv_param=b"",
                                         pin_uv_protocol=1)
        self.assertEqual(CtapError.ERR.PIN_INVALID, e.exception.code)

    def test_counter_increases_on_makecred(self):
        cred_res_1 = self.ctap2.make_credential(**self.basic_makecred_params)
        cred_res_2 = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(cred_res_2.auth_data.counter, cred_res_1.auth_data.counter + 1)

    def test_makecred_disallowed_by_exclude_list(self):
        cred_res_1 = self.ctap2.make_credential(**self.basic_makecred_params)
        cred_res_2 = self.ctap2.make_credential(**self.basic_makecred_params)
        exclude_c1 = copy.copy(self.basic_makecred_params)
        exclude_c1['exclude_list'] = [
            self.get_descriptor_from_ll_cred(cred_res_1)
        ]
        exclude_c2 = copy.copy(self.basic_makecred_params)
        exclude_c2['exclude_list'] = [
            self.get_descriptor_from_ll_cred(cred_res_2)
        ]

        with self.assertRaises(CtapError) as e1:
            self.ctap2.make_credential(**exclude_c1)
        with self.assertRaises(CtapError) as e2:
            self.ctap2.make_credential(**exclude_c2)

        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, e1.exception.code)
        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, e2.exception.code)

    def test_multiple_matching_rks(self):
        creds_to_make = 3
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        creds = []
        for x in range(creds_to_make):
            self.basic_makecred_params['user']['id'] = secrets.token_bytes(15)
            creds.append(self.ctap2.make_credential(**self.basic_makecred_params))

        asserts = [self.get_assertion(rp_id=self.rp_id)]
        self.assertEqual(creds_to_make, asserts[0].number_of_credentials)
        for x in range(creds_to_make - 1):
            asserts.append(self.ctap2.get_next_assertion())

        with self.assertRaises(CtapError) as e:
            self.ctap2.get_next_assertion()
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)
        self.assertEqual(sorted([x.auth_data.credential_data.credential_id for x in creds]),
                         sorted([x.credential['id'] for x in asserts])
                         )

    def test_makecred_rk_disallowed_by_exclude_list(self):
        non_resident_cred = self.ctap2.make_credential(**self.basic_makecred_params)
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        resident_cred = self.ctap2.make_credential(**self.basic_makecred_params)

        # Check that cred is, in fact, resident
        assert_res = self.get_assertion(rp_id=self.rp_id)
        self.assertEqual(self.basic_makecred_params['user']['id'],
                         assert_res.user['id'])

        self.basic_makecred_params['exclude_list'] = [
            self.get_descriptor_from_ll_cred(resident_cred)
        ]
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.basic_makecred_params['exclude_list'] = [
            self.get_descriptor_from_ll_cred(non_resident_cred)
        ]
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, e.exception.code)

    def test_ignored_allowlist_entry(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        self.get_assertion_from_cred(cred_res, client_data=self.get_random_client_data(),
                                     base_allow_list=[
                                         {
                                             "type": "bogus",
                                             "id": secrets.token_bytes(5)
                                         }
                                     ])

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
