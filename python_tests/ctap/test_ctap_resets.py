from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.webauthn import ResidentKeyRequirement
from parameterized import parameterized

from ctap.ctap_test import CTAPTestCase


class ResetTestCase(CTAPTestCase):

    @parameterized.expand([
        ("resident", True),
        ("nonresident", True),
    ])
    def test_reset_invalidates_creds(self, _, resident: bool):
        resident_key = ResidentKeyRequirement.REQUIRED if resident else ResidentKeyRequirement.DISCOURAGED
        client = self.get_high_level_client()

        cred = client.make_credential(options=self.get_high_level_make_cred_options(
            resident_key
        ))

        self.reset()

        with self.assertRaises(ClientError) as e:
            opts = self.get_high_level_assertion_opts_from_cred(None if resident else cred)
            client.get_assertion(options=opts)

        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, e.exception.cause.code)
