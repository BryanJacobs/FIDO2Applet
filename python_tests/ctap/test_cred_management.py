import secrets

from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.webauthn import ResidentKeyRequirement

from .ctap_test import FixedPinUserInteraction, CredManagementBaseTestCase


class CredManagementTestCase(CredManagementBaseTestCase):

    PERMISSION_CRED_MGMT = 4
    pin: str

    def test_cannot_enumerate_without_permission(self):
        cm = self.get_credential_management(permissions=0)

        with self.assertRaises(CtapError) as e:
            cm.enumerate_rps()

        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.exception.code)

    def test_cred_overwrites(self):
        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin)
        )

        for i in range(3):
            client.make_credential(options=self.get_high_level_make_cred_options(
                resident_key=ResidentKeyRequirement.REQUIRED
            ))

        cm = self.get_credential_management()
        rp_res = cm.enumerate_rps()
        self.assertEqual(1, len(rp_res))

        cred_res = cm.enumerate_creds(self.rp_id_hash(self.rp_id))
        self.assertEqual(1, len(cred_res))

    def test_cred_delete_rk(self):
        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin)
        )

        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))
        client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred=None))
        client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred))

        cm = self.get_credential_management()
        cm.delete_cred(
            self.get_descriptor_from_cred(cred)
        )

        with self.assertRaises(ClientError) as e:
            client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred))
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.cause.code)

    def test_rk_count(self):
        cm = self.get_credential_management()

        cred_info = cm.get_metadata()
        original_creds_remaining = cred_info[2]
        self.assertEqual(0, cred_info[1])

        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin)
        )
        client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))

        cred_info = self.get_credential_management().get_metadata()
        self.assertEqual(1, cred_info[1])
        self.assertEqual(original_creds_remaining - 1, cred_info[2])

    def test_cred_recreate_rk(self):
        client = self.get_high_level_client(
            user_interaction=FixedPinUserInteraction(self.pin)
        )

        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))

        cm = self.get_credential_management()
        cm.delete_cred(
            self.get_descriptor_from_cred(cred)
        )

        client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))

        # Fails with old cred ID in allowList - succeeds with nothing
        with self.assertRaises(ClientError) as e:
            client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred))
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.cause.code)
        client.get_assertion(self.get_high_level_assertion_opts_from_cred(cred=None))

    def test_cred_enumeration_after_deletes(self):
        creds_by_rp, rp_ids = self.setup_creds(3, 3)
        cm = self.get_credential_management()

        delete_everything_rp = rp_ids[0]
        delete_some_things_rp = rp_ids[-1]
        for cred in creds_by_rp[delete_everything_rp]:
            cm.delete_cred(self.get_descriptor_from_cred_id(cred))
        one_cred_to_delete = creds_by_rp[delete_some_things_rp][0]
        cm.delete_cred(self.get_descriptor_from_cred_id(one_cred_to_delete))

        rp_res = cm.enumerate_rps()
        gotten_rpids = [x[3]['id'] for x in rp_res]
        self.assertEqual([x for x in rp_ids if x != delete_everything_rp], gotten_rpids)

        rp_id_hash = self.rp_id_hash(delete_some_things_rp)
        cred_res = cm.enumerate_creds(rp_id_hash)
        creds = [x[7]['id'] for x in cred_res]
        expected_creds = [x for x in creds_by_rp[delete_some_things_rp] if x != one_cred_to_delete]
        self.assertEqual(sorted(expected_creds), sorted(creds))

    def test_cred_enumeration(self):
        creds_by_rp, rp_ids = self.setup_creds(3, 3)

        cm = self.get_credential_management()
        rp_res = cm.enumerate_rps()
        gotten_rpids = [x[3]['id'] for x in rp_res]
        self.assertEqual(rp_ids, gotten_rpids)

        for rp in rp_ids:
            rp_id_hash = self.rp_id_hash(rp)
            cred_res = cm.enumerate_creds(rp_id_hash)
            creds = [x[7]['id'] for x in cred_res]
            self.assertEqual(sorted(creds_by_rp[rp]), sorted(creds))

    def setup_creds(self, num_rps: int, num_creds_per_rp: int) -> tuple[dict[str, list[bytes]], list[str]]:
        rp_ids = []
        creds_by_rp = {}
        for rp_num in range(num_rps):
            rp_id = f'rp_{secrets.token_hex(3)}_no{rp_num}'
            origin = f'https://{rp_id}'
            client = self.get_high_level_client(
                user_interaction=FixedPinUserInteraction(self.pin),
                origin=origin
            )

            rp_ids.append(rp_id)
            creds_by_rp[rp_id] = []
            for cred_num in range(num_creds_per_rp):
                user = secrets.token_bytes(20)
                res = client.make_credential(options=self.get_high_level_make_cred_options(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    rp_id=rp_id,
                    user_id=user
                ))
                creds_by_rp[rp_id].append(res.attestation_object.auth_data.credential_data.credential_id)
        return creds_by_rp, rp_ids
