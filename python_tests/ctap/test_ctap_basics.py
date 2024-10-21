import copy
import secrets
import unittest

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.webauthn import Aaguid, ResidentKeyRequirement, UserVerificationRequirement

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class CTAPBasicsTestCase(CTAPTestCase):
    def test_info_supported_versions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["FIDO_2_0", "FIDO_2_1", "FIDO_2_1_PRE"], info.versions)

    def test_info_supported_extensions(self):
        info = self.ctap2.get_info()
        self.assertEqual([
            "uvm",
            "credBlob",
            "credProtect",
            "hmac-secret",
            "largeBlobKey",
            "minPinLength"
        ], info.extensions)

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

    def test_info_supported_options(self):
        info = self.ctap2.get_info()
        # This one can go either way depending on settings
        del info.options["makeCredUvNotRqd"]
        self.assertEqual({
            "uvAcfg": True,
            "alwaysUv": False,
            "authnrCfg": True,
            "clientPin": False,
            "credMgmt": True,
            #"ep": False,
            "largeBlobs": True,
            "pinUvAuthToken": True,
            "rk": True,
            "setMinPINLength": True,
            "up": False
        }, info.options)

    def test_info_aaguid_none(self):
        info = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info.aaguid)

    @unittest.skip("Providing this breaks the FIDO compliance test suite")
    def test_info_uv_modality_hint(self):
        info = self.ctap2.get_info()
        self.assertEqual(0x0200, info.uv_modality)

    def test_info_supported_algs_hint(self):
        info = self.ctap2.get_info()
        self.assertEqual([{'alg': -7, "type": "public-key"}], info.algorithms)

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
        self.assertEqual(112, len(res.auth_data.credential_data.credential_id))

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

    def test_get_assertion_returns_user_details_where_appropriate(self):
        pin = secrets.token_hex(5)
        ClientPin(self.ctap2).set_pin(pin)

        authed_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(pin))
        unauthed_client = self.get_high_level_client()

        cred = authed_client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))

        unauthed_assertion = unauthed_client.get_assertion(
            self.get_high_level_assertion_opts_from_cred(cred)
        ).get_assertions()[0]
        authed_assertion = authed_client.get_assertion(
            self.get_high_level_assertion_opts_from_cred(cred, user_verification=UserVerificationRequirement.REQUIRED)
        ).get_assertions()[0]

        self.assertEqual(self.basic_makecred_params['user']['id'], unauthed_assertion.user.get('id'))
        self.assertEqual(self.basic_makecred_params['user']['id'], authed_assertion.user.get('id'))
        self.assertIsNone(unauthed_assertion.user.get('name'))
        self.assertEqual(self.basic_makecred_params['user']['name'], authed_assertion.user.get('name'))

    def test_get_assertion_handles_nesting(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        self.ctap2.get_assertion(rp_id=self.rp_id,
                                 allow_list=[
                                     {
                                         "type": "public-key",
                                         "id": cred.auth_data.credential_data.credential_id,
                                         "transports": {
                                             "something": [1, 2, 3, 4]
                                         }
                                     }
                                 ],
                                 client_data_hash=secrets.token_bytes(32))

    def test_get_assertion_handles_extraneous_stuff(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        self.ctap2.get_assertion(rp_id=self.rp_id,
                                 allow_list=[
                                     {
                                         "type": "public-key",
                                         "id": cred.auth_data.credential_data.credential_id,
                                         "transports": [
                                             "usb",
                                             "nfc",
                                             "ble"
                                         ]
                                     }
                                 ],
                                 client_data_hash=secrets.token_bytes(32),
                                 extensions={
                                     "txAuthSimple": "Execute order 66."
                                 })

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
        self.assertTrue(cred_res_2.auth_data.counter > cred_res_1.auth_data.counter)

    def test_counter_allows_many_ops(self):
        cur_counter = 0
        for i in range(350):
            cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
            gotten_counter = cred_res.auth_data.counter
            self.assertTrue(gotten_counter > cur_counter)
            ctr_diff = abs(gotten_counter - cur_counter)
            self.assertTrue(ctr_diff <= 16)
            cur_counter = gotten_counter

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
        creds_to_make = 5
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        creds = []
        for x in range(creds_to_make):
            self.basic_makecred_params['user']['id'] = secrets.token_bytes(30)
            creds.append(self.ctap2.make_credential(**self.basic_makecred_params))

        asserts = [self.get_assertion(rp_id=self.rp_id)]
        self.assertEqual(creds_to_make, asserts[0].number_of_credentials)
        for x in range(creds_to_make - 1):
            asserts.append(self.ctap2.get_next_assertion())

        with self.assertRaises(CtapError) as e:
            self.ctap2.get_next_assertion()
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)
        self.assertEqual(
            [x.auth_data.credential_data.credential_id for x in creds][::-1],
            [x.credential['id'] for x in asserts]
        )

    def test_multiple_matching_rks_after_replacement(self):
        creds_to_make = 5
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        creds = []
        user_ids = []
        for x in range(creds_to_make):
            user_ids.append(secrets.token_bytes(30))
            self.basic_makecred_params['user']['id'] = user_ids[-1]
            creds.append(self.ctap2.make_credential(**self.basic_makecred_params))

        self.basic_makecred_params['user']['id'] = user_ids[1]
        replacement_cred = self.ctap2.make_credential(**self.basic_makecred_params)

        del creds[1]
        creds.append(replacement_cred)

        asserts = [self.get_assertion(rp_id=self.rp_id)]
        self.assertEqual(creds_to_make, asserts[0].number_of_credentials)
        for x in range(creds_to_make - 1):
            asserts.append(self.ctap2.get_next_assertion())

        with self.assertRaises(CtapError) as e:
            self.ctap2.get_next_assertion()
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.code)
        self.assertEqual(
            [x.auth_data.credential_data.credential_id for x in creds][::-1],
            [x.credential['id'] for x in asserts]
        )

    def test_accepts_long_utf8_display_name(self):
        self.basic_makecred_params['user']['display_name'] = "猫" * 144
        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_makecred_rk_max_len_user_id(self):
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(64)
        self.basic_makecred_params['options'] = {
            'rk': True
        }
        self.ctap2.make_credential(**self.basic_makecred_params)

        assert_res = self.get_assertion(rp_id=self.rp_id)
        self.assertEqual(self.basic_makecred_params['user']['id'],
                         assert_res.user['id'])

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
        self.assertTrue(assert_res_1.auth_data.counter > cred_res.auth_data.counter)
        self.assertTrue(assert_res_2.auth_data.counter > assert_res_1.auth_data.counter)

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

    def test_pin_uv_reuse(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        pin = secrets.token_hex(10)
        cp = ClientPin(self.ctap2)
        cp.set_pin(pin)
        uv = cp.get_pin_token(pin)
        assert_client_data = self.get_random_client_data()
        pin_uv_protocol = cp.protocol.VERSION
        pin_uv_param = cp.protocol.authenticate(uv, assert_client_data)

        assert_res1 = self.get_assertion_from_cred(cred_res, client_data=assert_client_data,
                                                   pin_uv_protocol=pin_uv_protocol,
                                                   pin_uv_param=pin_uv_param,
                                                   options={
                                                       'up': False
                                                   })
        assert_res2 = self.get_assertion_from_cred(cred_res, client_data=assert_client_data,
                                                   pin_uv_protocol=pin_uv_protocol,
                                                   pin_uv_param=pin_uv_param,
                                                   options={
                                                       'up': False
                                                   })
        assert_res3 = self.get_assertion_from_cred(cred_res, client_data=assert_client_data,
                                                   pin_uv_protocol=pin_uv_protocol,
                                                   pin_uv_param=pin_uv_param,
                                                   options={
                                                       'up': True
                                                   })
        error_raised = False
        try:
            self.get_assertion_from_cred(cred_res, client_data=assert_client_data,
                                         pin_uv_protocol=pin_uv_protocol,
                                         pin_uv_param=pin_uv_param,
                                         options={
                                            'up': False
                                         })
        except CtapError as e:
            self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.code)
            error_raised = True
        self.assertTrue(error_raised)
        for assert_res in [assert_res1, assert_res2, assert_res3]:
            self.assertEqual(cred_res.auth_data.credential_data.credential_id,
                             assert_res.credential['id'])

    def test_creds_are_tamper_resistant(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        cred_id = cred_res.auth_data.credential_data.credential_id

        for i in range(len(cred_id)):
            assert_client_data = self.get_random_client_data()
            cred_as_bl = list(cred_id)

            error_raised = False

            for x in range(5):
                munged_cred_id = bytearray(cred_as_bl[:i] + [((cred_as_bl[i] + 1 + x) % 128)] + cred_as_bl[i+1:])

                try:
                    self.ctap2.get_assertion(
                        client_data_hash=assert_client_data,
                        allow_list=[self.get_descriptor_from_cred_id(munged_cred_id)],
                        rp_id=self.rp_id
                    )
                except CtapError as e:
                    self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.code)
                    error_raised = True
                    break

            self.assertTrue(error_raised)

        self.ctap2.get_assertion(
            client_data_hash=self.get_random_client_data(),
            allow_list=[self.get_descriptor_from_cred_id(cred_id)],
            rp_id=self.rp_id
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
