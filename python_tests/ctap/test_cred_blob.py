import secrets

from .ctap_test import CTAPTestCase


class CredBlobTestCase(CTAPTestCase):

    def store_cred_blob(self, blob: bytes):
        return self.ctap2.make_credential(**self.basic_makecred_params,
                                          options={
                                              "rk": True
                                          },
                                          extensions={
                                              "credBlob": blob
                                          })

    def test_cred_blob_fails_on_non_rk(self):
        blob = secrets.token_bytes(32)

        res = self.ctap2.make_credential(**self.basic_makecred_params,
                                          extensions={
                                              "credBlob": blob
                                          })
        self.assertEqual({
            "credBlob": False
        }, res.auth_data.extensions)

    def test_cred_blob_fails_on_long_blob(self):
        blob = secrets.token_bytes(33)

        res = self.store_cred_blob(blob)

        self.assertEqual({
            "credBlob": False
        }, res.auth_data.extensions)

    def test_cred_blob_make_credential(self):
        blob = secrets.token_bytes(32)

        res = self.store_cred_blob(blob)

        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual({
            "credBlob": True
        }, res.auth_data.extensions)

    def test_cred_blob_retrieval(self):
        blob = secrets.token_bytes(32)
        self.store_cred_blob(blob)

        self.softResetCard()

        res = self.get_assertion_from_cred(cred=None, rp_id=self.rp_id, extensions={"credBlob": True})

        self.assertEqual({
            "credBlob": blob
        }, res.auth_data.extensions)

    def test_retrieving_short_cred(self):
        blob = secrets.token_bytes(3)
        self.store_cred_blob(blob)

        res = self.get_assertion_from_cred(cred=None, rp_id=self.rp_id, extensions={"credBlob": True})

        self.assertEqual({
            "credBlob": blob
        }, res.auth_data.extensions)
