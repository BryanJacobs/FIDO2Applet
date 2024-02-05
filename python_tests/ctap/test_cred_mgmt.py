import secrets

from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import ResidentKeyRequirement, PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor
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

        self.assertLessEqual(dcs_before - 1, dcs_after_creation)
        self.assertEqual(dcs_before, dcs_after_deletion)

    def test_deleting_one_rk_for_rp(self):
        rp_id = 'a'
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(self.pin),
                                            origin = 'https://' + rp_id)
        resident_key = ResidentKeyRequirement.REQUIRED

        cm = self.get_credential_management()

        rps = cm.enumerate_rps()
        self.assertEqual(0, len(rps))
        user_id_1 = b'abc'
        user_id_2 = b'def'

        cred1 = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED
            },
            rp_id=rp_id,
            user_id=user_id_1
        ))
        cred2 = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key,
            {
                "credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED
            },
            rp_id=rp_id,
            user_id=user_id_2
        ))
        self.assertNotEqual(
            cred1.attestation_object.auth_data.credential_data.credential_id,
            cred2.attestation_object.auth_data.credential_data.credential_id,
        )
        cm = self.get_credential_management()
        rps = cm.enumerate_rps()
        self.assertEqual(1, len(rps))

        for rp in rps:
            self.assertEqual(rp_id, rp[3]['id'])
            self.assertEqual(self.rp_id_hash(rp_id).hex(), rp[4].hex())

        creds = cm.enumerate_creds(rp_id_hash=self.rp_id_hash(rp_id))
        self.assertEqual(2, len(creds))

        cm.delete_cred(self.get_descriptor_from_cred_id(
            cred1.attestation_object.auth_data.credential_data.credential_id
        ))

        cm = self.get_credential_management()
        rps = cm.enumerate_rps()
        self.assertEqual(1, len(rps))

    def test_creating_many_rks(self):
        client = self.get_high_level_client(extensions=[CredProtectExtension],
                                            user_interaction=FixedPinUserInteraction(self.pin))
        client._verify_rp_id = lambda x: True
        resident_key = ResidentKeyRequirement.REQUIRED
        first_cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key
        ))
        for x in range(100):
            rp_id = secrets.token_hex(20)
            client.make_credential(options=self.get_high_level_make_cred_options(
                resident_key, rp_id=rp_id
            ))

        res = client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred=None, rp_id=self.rp_id))
        assertions = res.get_assertions()
        self.assertEqual(1, len(assertions))
        self.assertEqual(res.get_response(0).credential_id,
                         first_cred.attestation_object.auth_data.credential_data.credential_id)

    def test_enumerating_mixed_security_creds(self):
        pin_client = self.get_high_level_client(extensions=[CredProtectExtension],
                                                user_interaction=FixedPinUserInteraction(self.pin))
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

    def test_updating_user(self):
        pin_client = self.get_high_level_client(user_interaction=FixedPinUserInteraction(self.pin))
        cred = pin_client.make_credential(options=self.get_high_level_make_cred_options(
            ResidentKeyRequirement.REQUIRED
        ))
        cm = self.get_credential_management()
        new_id = secrets.token_bytes(64)
        new_name = "Frooby Bobble"

        cm.update_user_info(cred_id=PublicKeyCredentialDescriptor(
            type='public-key',
            id=cred.attestation_object.auth_data.credential_data.credential_id
        ), user_info=PublicKeyCredentialUserEntity(
            id=new_id,
            name=new_name,
            display_name='Some very long stuff that makes this inconvenient to work with'
        ))

        cm = self.get_credential_management()
        after_cred = cm.enumerate_creds(rp_id_hash=self.rp_id_hash(self.rp_id))[0]
        self.assertEqual(new_id, after_cred[6].get('id'))
        self.assertEqual(new_name, after_cred[6].get('name'))
