import secrets

from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement
from parameterized import parameterized

from .ctap_test import CTAPTestCase, FixedPinUserInteraction, CredManagementBaseTestCase
from .test_cred_management import CredManagementTestCase


class CredProtectTestCase(CTAPTestCase):

    @parameterized.expand([
        ("Fails with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED, False, False),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL, False, True),
        ("Fails with resident level 3", 3, CredProtectExtension.POLICY.REQUIRED, True, False),
        ("Fails with resident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST, True, False),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL, True, True),
    ])
    def test_cred_protect_without_pin(self, _, level, policy, resident, expect_success):
        client = self.get_high_level_client(extensions=[CredProtectExtension])
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED

        def do(thing):
            if expect_success:
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
        )))
        if expect_success:
            self.assertEqual(level, res.attestation_object.auth_data.extensions.get('credProtect'))
        else:
            self.assertEqual(CtapError.ERR.OPERATION_DENIED, res.code)

    @parameterized.expand([
        ("Succeeds with nonresident level 3", 3, CredProtectExtension.POLICY.REQUIRED, False, True),
        ("Succeeds with nonresident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST, False, True),
        ("Succeeds with nonresident level 1", 1, CredProtectExtension.POLICY.OPTIONAL, False, True),
        ("Succeeds with resident level 3", 3, CredProtectExtension.POLICY.REQUIRED, True, True),
        ("Succeeds with resident level 2", 2, CredProtectExtension.POLICY.OPTIONAL_WITH_LIST, True, True),
        ("Succeeds with resident level 1", 1, CredProtectExtension.POLICY.OPTIONAL, True, True),
    ])
    def test_cred_protect_with_pin(self, _, level, policy, resident, expect_success):
        pin = secrets.token_hex(8)
        ClientPin(self.ctap2).set_pin(pin)
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(pin))
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED

        def do(thing):
            if expect_success:
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
        )))
        if expect_success:
            self.assertEqual(level, res.attestation_object.auth_data.extensions.get('credProtect'))
        else:
            self.assertEqual(CtapError.ERR.OPERATION_DENIED, res.code)


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
