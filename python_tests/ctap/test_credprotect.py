import secrets

from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement
from parameterized import parameterized

from .ctap_test import CTAPTestCase, FixedPinUserInteraction, CredManagementBaseTestCase


class CredProtectTestCase(CTAPTestCase):

    def cred_protect_using_client(self, client, level, policy,
                                      resident, create_success, discoverable_afterwards, usable_afterwards):
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED

        def do(thing, expectation):
            if expectation:
                return thing()
            else:
                with self.assertRaises(ClientError) as e:
                    thing()
                return e.exception.cause

        res = do(lambda: client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": policy
            }
        )), expectation=create_success)
        if create_success:
            self.assertEqual(level, res.attestation_object.auth_data.extensions.get('credProtect'))

            if discoverable_afterwards is not None:
                opts = self.get_high_level_assertion_opts_from_cred(cred=None)
                assert_res = do(lambda: client.get_assertion(opts), expectation=discoverable_afterwards)
                if not discoverable_afterwards:
                    self.assertEqual(CtapError.ERR.NO_CREDENTIALS, assert_res.code)

            if usable_afterwards is not None:
                opts = self.get_high_level_assertion_opts_from_cred(cred=res)
                assert_res = do(lambda: client.get_assertion(opts), expectation=usable_afterwards)
                if not usable_afterwards:
                    self.assertEqual(CtapError.ERR.NO_CREDENTIALS, assert_res.code)
        else:
            self.assertEqual(CtapError.ERR.OPERATION_DENIED, res.code)

    @parameterized.expand([
        ("Fails with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
            False, False, None, None),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
            False, True, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
            False, True, False, True),
        ("Succeeds with resident level 3, unusable afterwards", 3, CredProtectExtension.POLICY.REQUIRED,
            True, True, False, False),
        ("Succeeds with resident level 2, but non-discoverable", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
            True, True, False, True),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
            True, True, True, True),
    ])
    def test_cred_protect_without_pin(self, _, level, policy,
                                      resident, create_success, discoverable_afterwards, usable_afterwards):
        client = self.get_high_level_client(extensions=[CredProtectExtension])
        self.cred_protect_using_client(client, level, policy,
                                       resident, create_success, discoverable_afterwards, usable_afterwards)

    @parameterized.expand([
        ("Succeeds with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         False, True, False, True),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         False, True, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
         False, True, False, True),
        ("Succeeds with resident level 3", 3, CredProtectExtension.POLICY.REQUIRED,
         True, True, True, True),
        ("Succeeds with resident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
         True, True, True, True),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL,
         True, True, True, True),
    ])
    def test_cred_protect_with_pin(self, _, level, policy,
                                   resident, create_success, discoverable_afterwards, usable_afterwards):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(pin))

        self.cred_protect_using_client(client, level, policy,
                                       resident, create_success, discoverable_afterwards, usable_afterwards)


class CredProtectRKVisTestCase(CredManagementBaseTestCase):
    @parameterized.expand([
        ("Level 3", 3, CredProtectExtension.POLICY.REQUIRED),
        ("Level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST),
        ("Level 1", 1, CredProtectExtension.POLICY.OPTIONAL),
        ("Omitted", 0, None),
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
