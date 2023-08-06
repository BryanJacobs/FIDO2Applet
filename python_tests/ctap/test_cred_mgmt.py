import secrets

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

    def test_enumerating_mixed_security_creds(self):
        pin_client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(self.pin))
        no_pin_client = self.get_high_level_client(extensions=[CredProtectExtension])
        resident_key = ResidentKeyRequirement.REQUIRED
        hs_cred = pin_client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED
            }
        ))
        other_rp = secrets.token_hex(18)
        pin_client_other_suffix = self.get_high_level_client(extensions=[CredProtectExtension],
                                                             user_interaction=FixedPinUserInteraction(self.pin),
                                                             origin='https://' + other_rp)
        other_hs_cred = pin_client_other_suffix.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED
            },
            rp_id=other_rp
        ))
        self.softResetCard()
        self.basic_makecred_params['options'] = {'rk': True}
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(20)
        ls_cred = self.ctap2.make_credential(**self.basic_makecred_params)

        info = self.ctap2.get_info()
        self.assertEqual(47, info.remaining_disc_creds)

        rps = self.get_credential_management().enumerate_rps()
        self.assertEqual(2, len(rps))

        creds = self.get_credential_management().enumerate_creds(rp_id_hash=self.rp_id_hash(self.rp_id))
        other_creds = self.get_credential_management().enumerate_creds(rp_id_hash=self.rp_id_hash(other_rp))

        self.assertEqual(1, len(other_creds))
        self.assertEqual(2, len(creds))

        cred_levels = [x[10] for x in creds]
        cred_ids = [x[7]['id'] for x in creds]
        self.assertEqual([1, 3], sorted(cred_levels))
        self.assertEqual(sorted([ls_cred.auth_data.credential_data.credential_id,
                          hs_cred.attestation_object.auth_data.credential_data.credential_id]),
                         sorted(cred_ids))

        self.assertEqual(3, other_creds[0][10])
        self.assertEqual(other_hs_cred.attestation_object.auth_data.credential_data.credential_id,
                         other_creds[0][7]['id'])
