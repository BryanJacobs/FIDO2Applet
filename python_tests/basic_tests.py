#!/usr/bin/env python
import random
from typing import Optional, Type
import secrets

import fido2.features
from fido2.client import Fido2Client, UserInteraction, PinRequiredError, ClientError
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import HmacSecretExtension, Ctap2Extension
from fido2.webauthn import Aaguid, PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, \
    PublicKeyCredentialUserEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, \
    AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement, \
    PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor
from parameterized import parameterized

from .ctap_test_base import CTAPTestCase

fido2.features.webauthn_json_mapping.enabled = False


class FixedPinUserInteraction(UserInteraction):
    pin: str

    def __init__(self, pin: str):
        self.pin = pin

    def request_pin(
            self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> Optional[str]:
        return self.pin


class FIDOTesting(CTAPTestCase):
    client_data: bytes
    basic_makecred_params = {
        "rp": {},
        "user": {},
        "key_params": [
            {
                "type": "public-key",
                "alg": ES256.ALGORITHM
            }
        ],
    }

    def setUp(self) -> None:
        super().setUp()
        self.client_data = self.get_random_client_data()
        self.basic_makecred_params["client_data_hash"] = self.client_data
        rpid_length = random.randint(1, 32)
        self.basic_makecred_params['rp']['id'] = secrets.token_hex(rpid_length)
        userid_length = random.randint(1, 64)
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(userid_length)

    @staticmethod
    def get_random_client_data():
        return secrets.token_bytes(32)

    def test_info_supported_versions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["FIDO_2_0", "FIDO_2_1"], info.versions)

    def test_info_supported_extensions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["credProtect", "hmac-secret"], info.extensions)

    def test_make_credential_self_attestation(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertIsNone(res.ep_att)
        self.assertIsNone(res.auth_data.extensions)
        self.assertIsNotNone(res.att_stmt)
        self.assertIsNone(res.large_blob_key)
        self.assertEqual(res.auth_data.FLAG.UP | res.auth_data.FLAG.ATTESTED, res.auth_data.flags)

        self.assertEqual(ES256.ALGORITHM, res.att_stmt['alg'])
        self.assertIsNotNone(res.att_stmt['sig'])
        self.assertEqual(Aaguid.NONE, res.auth_data.credential_data.aaguid)

        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual(64, len(res.auth_data.credential_data.credential_id))

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

    def test_pin_change(self):
        first_pin = secrets.token_hex(16)
        second_pin = secrets.token_hex(16)
        old_pin_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(first_pin))
        new_pin_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(second_pin))
        cp = ClientPin(self.ctap2)

        cp.set_pin(first_pin)
        cp.change_pin(first_pin, second_pin)
        with self.assertRaises(ClientError) as e:
            # Old PIN is now wrong
            old_pin_client.make_credential(self.get_make_cred_options())

        # New PIN is correct
        new_pin_client.make_credential(self.get_make_cred_options())

        self.assertEqual(CtapError.ERR.PIN_INVALID, e.exception.cause.code)

    def test_pin_change_providing_incorrect_old_pin(self):
        first_pin = secrets.token_hex(16)
        second_pin = secrets.token_hex(16)
        cp = ClientPin(self.ctap2)
        cp.set_pin(first_pin)

        with self.assertRaises(CtapError) as e:
            cp.change_pin("12345", second_pin)

        self.assertEqual(CtapError.ERR.PIN_INVALID, e.exception.code)

    @parameterized.expand([
        ("short", 1, False),
        ("minimal", 2, True),
        ("reasonable", 8, True),
        ("maximal", 31, True),
        ("overlong", 32, False),
        ("huge", 40, False),
    ])
    def test_pin_lengths(self, _, length, valid):
        pin = secrets.token_hex(length)

        def do_client_pin():
            pin_as_bytes = pin.encode()
            while len(pin_as_bytes) < 64:
                pin_as_bytes += b'\0'

            cp = ClientPin(self.ctap2)
            ka, ss = cp._get_shared_secret()
            enc = cp.protocol.encrypt(ss, pin_as_bytes)
            puv = cp.protocol.authenticate(ss, enc)
            self.ctap2.client_pin(
                2,
                ClientPin.CMD.SET_PIN,
                key_agreement=ka,
                new_pin_enc=enc,
                pin_uv_param=puv
            )

        if valid:
            do_client_pin()
        else:
            with self.assertRaises(CtapError) as e:
                do_client_pin()

            self.assertEqual(CtapError.ERR.PIN_POLICY_VIOLATION, e.exception.code)

    def test_pin_set_and_not_provided_library_level(self):
        pin = secrets.token_hex(30)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client()

        with self.assertRaises(PinRequiredError):
            client.make_credential(options=self.get_make_cred_options())

    def test_pin_set_and_not_provided_underyling_impl(self):
        pin = secrets.token_hex(30)
        ClientPin(self.ctap2).set_pin(pin)

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    def get_make_cred_options(self,
                              resident_key: ResidentKeyRequirement = ResidentKeyRequirement.DISCOURAGED,
                              extensions=None) -> PublicKeyCredentialCreationOptions:
        if extensions is None:
            extensions = {}

        return PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(
                name="An RP Name",
                id=self.basic_makecred_params['rp']['id']
            ),
            user=PublicKeyCredentialUserEntity(
                name="Bob",
                id=self.basic_makecred_params['user']['id']
            ),
            challenge=self.client_data,
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=ES256.ALGORITHM
                )
            ],
            extensions=extensions,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=resident_key,
                user_verification=UserVerificationRequirement.DISCOURAGED
            )
        )

    def get_high_level_client(self, extensions: Optional[list[Type[Ctap2Extension]]] = None,
                              user_interaction: UserInteraction = None) -> Fido2Client:
        if extensions is None:
            extensions = []
        if user_interaction is None:
            user_interaction = UserInteraction()
        return Fido2Client(self.device, "https://" + self.basic_makecred_params['rp']['id'],
                           extension_types=extensions, user_interaction=user_interaction)

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

        cred = client.make_credential(options=self.get_make_cred_options(
            resident_key,
            {
                "hmacCreateSecret": True
            }
        ))
        self.assertEqual({"hmacCreateSecret": True}, cred.extension_results)

        assert_client_data = self.get_random_client_data()
        assertion_allow_credentials = []
        if not resident:
            assertion_allow_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred.attestation_object.auth_data.credential_data.credential_id
                )
            ]

        def get_assertion(given_salt):
            assertions = client.get_assertion(options=PublicKeyCredentialRequestOptions(
                challenge=assert_client_data,
                rp_id=self.basic_makecred_params['rp']['id'],
                allow_credentials=assertion_allow_credentials,
                user_verification=UserVerificationRequirement.DISCOURAGED,
                extensions={
                    "hmacGetSecret": {
                        "salt1": given_salt
                    }
                }
            ))
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

    def test_basic_assertion(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)

        assert_client_data = self.get_random_client_data()

        assert_res = self.ctap2.get_assertion(
            rp_id=self.basic_makecred_params['rp']['id'],
            client_data_hash=assert_client_data,
            allow_list=[
                {
                    "type": "public-key",
                    "id": cred_res.auth_data.credential_data.credential_id
                }
            ]
        )
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
