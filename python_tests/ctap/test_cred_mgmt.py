from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement
from parameterized import parameterized

from ctap.ctap_test import CredManagementBaseTestCase, FixedPinUserInteraction


class CredManagementTestCase(CredManagementBaseTestCase):
    @parameterized.expand([
        ("low", CredProtectExtension.POLICY.OPTIONAL),
        ("medium", CredProtectExtension.POLICY.OPTIONAL_WITH_LIST),
        ("high", CredProtectExtension.POLICY.REQUIRED),
    ])
    def test_deleting_rk(self, _, policy):
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(self.pin))
        resident_key = ResidentKeyRequirement.REQUIRED

        dcs_before = self.ctap2.get_info().remaining_disc_creds
        res = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": policy
            }
        ))
        dcs_after_creation = self.ctap2.get_info().remaining_disc_creds
        cm = self.get_credential_management()
        cm.delete_cred(self.get_descriptor_from_cred_id(
            res.attestation_object.auth_data.credential_data.credential_id
        ))
        dcs_after_deletion = self.ctap2.get_info().remaining_disc_creds

        self.assertEqual(dcs_before - 1, dcs_after_creation)
        self.assertEqual(dcs_before, dcs_after_deletion)
