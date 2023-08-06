import secrets
import unittest

from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement, UserVerificationRequirement
from parameterized import parameterized

from .ctap_test import CTAPTestCase, FixedPinUserInteraction, CredManagementBaseTestCase


class CredProtectTestCase(CTAPTestCase):

    def cred_protect_using_client(self, client, level, policy, use_pin: UserVerificationRequirement,
                                  resident, discoverable_afterwards, usable_afterwards):
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED

        def do(thing, expectation):
            if expectation:
                return thing()
            else:
                with self.assertRaises(ClientError) as e:
                    thing()
                return e.exception.cause

        res = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        self.assertEqual(level, res.attestation_object.auth_data.extensions.get('credProtect'))

        self.softResetCard()  # Ensure everything is cleared from memory

        if discoverable_afterwards is not None:
            opts = self.get_high_level_assertion_opts_from_cred(cred=None, user_verification=use_pin)
            assert_res = do(lambda: client.get_assertion(opts), expectation=discoverable_afterwards)
            if not discoverable_afterwards:
                self.assertEqual(CtapError.ERR.NO_CREDENTIALS, assert_res.code)

        if usable_afterwards is not None:
            opts = self.get_high_level_assertion_opts_from_cred(cred=res, user_verification=use_pin)
            assert_res = do(lambda: client.get_assertion(opts), expectation=usable_afterwards)
            if not usable_afterwards:
                self.assertEqual(CtapError.ERR.NO_CREDENTIALS, assert_res.code)

    @parameterized.expand([
        ("Unusable afterwards with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
            False, False, False),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
            False, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
            False, False, True),
        ("Succeeds with resident level 3, unusable afterwards", 3, CredProtectExtension.POLICY.REQUIRED,
            True, False, False),
        ("Non-discoverable with resident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
            True, False, True),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
            True, True, True),
    ])
    def test_cred_protect_without_pin(self, _, level, policy,
                                      resident, discoverable_afterwards, usable_afterwards):
        self.cred_protect_using_client(self.get_high_level_client(extensions=[CredProtectExtension]), level, policy,
                                       UserVerificationRequirement.DISCOURAGED,
                                       resident, discoverable_afterwards, usable_afterwards)

    @parameterized.expand([
        ("Succeeds with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         False, False, True),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         False, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
         False, False, True),
        ("Succeeds with resident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         True, True, True),
        ("Succeeds with resident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         True, True, True),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
         True, True, True),
    ])
    def test_cred_protect_with_pin(self, _, level, policy,
                                   resident, discoverable_afterwards, usable_afterwards):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        ux = FixedPinUserInteraction(pin)

        self.cred_protect_using_client(self.get_high_level_client(extensions=[CredProtectExtension],
                                                                  user_interaction=ux),
                                       level, policy, UserVerificationRequirement.REQUIRED,
                                       resident, discoverable_afterwards, usable_afterwards)

    @parameterized.expand([
        ("Unusable afterwards with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         False, False, False),
        ("Non-discoverable with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         False, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
         False, False, True),
        ("Unusable afterwards with resident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         True, False, False),
    ])
    def test_cred_protect_pin_on_creation_but_not_use(self, _, level, policy,
                                   resident, discoverable_afterwards, usable_afterwards):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        ux = FixedPinUserInteraction(pin)

        self.cred_protect_using_client(self.get_high_level_client(extensions=[CredProtectExtension],
                                                                  user_interaction=ux),
                                       level, policy, UserVerificationRequirement.DISCOURAGED,
                                       resident, discoverable_afterwards, usable_afterwards)

    @parameterized.expand([
        ("Resident level 2 unusable without PIN", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         True, False, False),
        ("Resident level 1 unusable without PIN", 1, CredProtectExtension.POLICY.OPTIONAL,
         True, False, False),
    ])
    @unittest.skip("Depends on RK security level")
    def test_deviations_from_expectations(self, _, level, policy,
                                          resident, discoverable_afterwards, usable_afterwards):
        """
        These are tests that describe deviations from CTAP standard expectations.

        These tests will pass if USE_LOW_SECURIY_FOR_SOME_RKS is false (high security mode), and fail otherwise.
        """
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        ux = FixedPinUserInteraction(pin)

        self.cred_protect_using_client(self.get_high_level_client(extensions=[CredProtectExtension],
                                                                  user_interaction=ux),
                                       level, policy, UserVerificationRequirement.DISCOURAGED,
                                       resident, discoverable_afterwards, usable_afterwards)

    def test_strong_protected_creds_ignored_on_exclude_list_without_pin(self):
        policy = CredProtectExtension.POLICY.REQUIRED
        client = self.get_high_level_client(extensions=[CredProtectExtension])
        res = client.make_credential(options=self.get_high_level_make_cred_options(
            ResidentKeyRequirement.DISCOURAGED,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        self.basic_makecred_params['exclude_list'] = [{
            "type": "public-key",
            "id": res.attestation_object.auth_data.credential_data.credential_id
        }]

        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_level_3_protected_creds_ignored_on_exclude_list_without_pin(self):
        policy = CredProtectExtension.POLICY.REQUIRED
        client = self.get_high_level_client(extensions=[CredProtectExtension])
        res = client.make_credential(options=self.get_high_level_make_cred_options(
            ResidentKeyRequirement.REQUIRED,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        self.basic_makecred_params['exclude_list'] = [{
            "type": "public-key",
            "id": res.attestation_object.auth_data.credential_data.credential_id
        }]

        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_level_2_protected_creds_effective_on_exclude_list_without_pin(self):
        policy = CredProtectExtension.POLICY.OPTIONAL_WITH_LIST
        client = self.get_high_level_client(extensions=[CredProtectExtension])
        res = client.make_credential(options=self.get_high_level_make_cred_options(
            ResidentKeyRequirement.REQUIRED,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        self.basic_makecred_params['exclude_list'] = [{
            "type": "public-key",
            "id": res.attestation_object.auth_data.credential_data.credential_id
        }]

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, e.exception.code)


class CredProtectRKVisTestCase(CredManagementBaseTestCase):
    @parameterized.expand([
        ("Level 3", 3, CredProtectExtension.POLICY.REQUIRED),
        ("Level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST),
        ("Level 1", 1, CredProtectExtension.POLICY.OPTIONAL),
        ("Omitted", 1, None),
    ])
    def test_cred_protect_level_rk_visibility(self, _, level, policy):
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(self.pin))
        resident_key = ResidentKeyRequirement.REQUIRED

        res = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        extensions = res.attestation_object.auth_data.extensions
        if policy is None:
            self.assertIsNone(extensions)
        else:
            self.assertEqual(level, extensions['credProtect'])

        cm = self.get_credential_management()
        creds = cm.enumerate_creds(self.rp_id_hash(self.rp_id))
        self.assertEqual(1, len(creds))
        self.assertEqual(level, creds[0][10])
