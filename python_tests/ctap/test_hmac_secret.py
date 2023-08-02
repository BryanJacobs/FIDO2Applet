import secrets

from parameterized import parameterized
from fido2.client import UserInteraction
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.webauthn import ResidentKeyRequirement, AuthenticatorAssertionResponse, UserVerificationRequirement

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class HMACSecretTestCase(CTAPTestCase):

    def test_hmac_secret_make_credential(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params,
                                         extensions={
                                             "hmac-secret": True
                                         })

        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual({
            "hmac-secret": True
        }, res.auth_data.extensions)

    def get_hmacs_from_result(self, assertion: AuthenticatorAssertionResponse) -> tuple[str, str]:
        return (assertion.extension_results['hmacGetSecret'].get('output1'),
               assertion.extension_results['hmacGetSecret'].get('output2'))

    def test_uv_and_non_uv_yield_different_values(self):
        no_pin_client = self.get_high_level_client(extensions=[HmacSecretExtension])
        cred = no_pin_client.make_credential(options=self.get_high_level_make_cred_options(
            extensions={
                "hmacCreateSecret": True
            }
        ))
        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)

        assertion_before = no_pin_client.get_assertion(
            self.get_high_level_assertion_opts_from_cred(cred,
                                                         extensions={
                                                            "hmacGetSecret": {
                                                                "salt1": salt1,
                                                                "salt2": salt2,
                                                            }
                                                        })
        )

        pin = secrets.token_hex(30)
        ClientPin(self.ctap2).set_pin(pin)
        pin_client = self.get_high_level_client(extensions=[HmacSecretExtension],
                                                user_interaction=FixedPinUserInteraction(pin))
        assertion_after = pin_client.get_assertion(
            self.get_high_level_assertion_opts_from_cred(cred,
                                                         user_verification=UserVerificationRequirement.REQUIRED,
                                                         extensions={
                                                             "hmacGetSecret": {
                                                                 "salt1": salt1,
                                                                 "salt2": salt2,
                                                             }
                                                         })
        )

        before1, before2 = self.get_hmacs_from_result(assertion_before.get_response(0))
        after1, after2 = self.get_hmacs_from_result(assertion_after.get_response(0))

        self.assertNotEqual(before1, after1)
        self.assertNotEqual(before1, before2)
        self.assertNotEqual(before2, after2)
        self.assertNotEqual(after1, after2)

    @parameterized.expand([
        ("nonresident+nopin", False, False),
        ("resident+nopin", True, False),
        ("nonresident+pin", False, True),
        ("resident+pin", True, True),
    ])
    def test_hmac_secret_usage(self, _, resident, pin_set):
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED

        user_interaction = UserInteraction()
        if pin_set:
            pin = secrets.token_hex(30)
            user_interaction = FixedPinUserInteraction(pin)
            ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[HmacSecretExtension],
                                            user_interaction=user_interaction)

        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "hmacCreateSecret": True
            }
        ))
        self.assertEqual({"hmacCreateSecret": True}, cred.extension_results)

        assert_client_data = self.get_random_client_data()

        def get_assertion(given_salt):
            opts = self.get_high_level_assertion_opts_from_cred(None if resident else cred,
                                                                client_data=assert_client_data, rp_id=self.rp_id,
                                                                extensions={
                                                                    "hmacGetSecret": {
                                                                        "salt1": given_salt
                                                                    }
                                                                })
            assertions = client.get_assertion(options=opts)
            # TODO: verify
            # cred_public_key = cred.attestation_object.auth_data.credential_data.public_key
            # cred_public_key.verify(assertion.authenticator_data + assert_client_data,
            #                          assertion.signature)
            self.assertEqual(1, len(assertions.get_assertions()))
            assertion = assertions.get_response(0)
            hmac = assertion.extension_results['hmacGetSecret']['output1']
            self.assertEqual(32, len(hmac))
            return hmac

        salt1 = b"x" * 32
        salt2 = b"y" * 32

        # If hmac-secret is working properly, it should give the same result
        # ... when provided with the same salt, and different results otherwise
        hmac_secret_result = get_assertion(salt1)
        hmac_secret_result_2 = get_assertion(salt1)
        hmac_secret_result_3 = get_assertion(salt2)

        self.assertEqual(hmac_secret_result, hmac_secret_result_2)
        self.assertNotEqual(hmac_secret_result, hmac_secret_result_3)
