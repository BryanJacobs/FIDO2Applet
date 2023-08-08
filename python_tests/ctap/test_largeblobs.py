import copy
import secrets

from cryptography.hazmat.primitives import hashes
from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import AttestationResponse, LargeBlobs, ClientPin, PinProtocolV2
from fido2.ctap2.extensions import LargeBlobExtension
from fido2.webauthn import ResidentKeyRequirement
from parameterized import parameterized

from .ctap_test import BasicAttestationTestCase


class LargeBlobsTestCase(BasicAttestationTestCase):

    def test_info_shows_largeblobkey(self):
        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("largeBlobs"))

    def test_makecred_largeblob_rejected_on_false(self):
        self.basic_makecred_params['extensions'] = {
            'largeBlobKey': False
        }
        self.basic_makecred_params['options'] = {
            'rk': True
        }

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.INVALID_OPTION, e.exception.code)

    def make_large_blob_key(self) -> AttestationResponse:
        params = copy.copy(self.basic_makecred_params)
        params['extensions'] = {
            'largeBlobKey': True
        }
        params['options'] = {
            'rk': True
        }
        return self.ctap2.make_credential(**params)

    def test_makecred_with_largeblob(self):
        cred = self.make_large_blob_key()

        self.assertIsNotNone(cred.large_blob_key)
        self.assertEqual(32, len(cred.large_blob_key))

    def test_discover_largeblobkey(self):
        cred = self.make_large_blob_key()

        assertion = self.get_assertion(rp_id=self.rp_id, extensions={"largeBlobKey": True})

        self.assertEqual(cred.large_blob_key, assertion.large_blob_key)

    def test_get_does_not_require_pin(self):
        ClientPin(self.ctap2).set_pin("12345")

        res = LargeBlobs(self.ctap2).read_blob_array()

        self.assertEqual([], res)

    def test_set_requires_pin(self):
        ClientPin(self.ctap2).set_pin("12345")

        with self.assertRaises(CtapError) as e:
            LargeBlobs(self.ctap2).write_blob_array([1, 2, 3])

        self.assertEqual(CtapError.ERR.PUAT_REQUIRED, e.exception.code)

    def test_set_with_pin_no_permissions(self):
        pin = secrets.token_hex(10)
        cp = ClientPin(self.ctap2)
        cp.set_pin(pin)
        uv = cp.get_pin_token(pin)
        lb = LargeBlobs(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)

        with self.assertRaises(CtapError) as e:
            lb.write_blob_array([1, 2, 3])

        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.exception.code)

    def test_set_with_pin_with_permission(self):
        pin = secrets.token_hex(10)
        cp = ClientPin(self.ctap2)
        cp.set_pin(pin)
        uv = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.LARGE_BLOB_WRITE)

        lb = LargeBlobs(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)
        lb.write_blob_array([1, 2, 3])

    def test_set_with_pin_without_permission(self):
        pin = secrets.token_hex(10)
        cp = ClientPin(self.ctap2)
        cp.set_pin(pin)
        uv = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        lb = LargeBlobs(self.ctap2, pin_uv_protocol=PinProtocolV2(), pin_uv_token=uv)

        with self.assertRaises(CtapError) as e:
            lb.write_blob_array([1, 2, 3])

        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, e.exception.code)

    def test_discover_largeblobkey_with_basic_cert(self):
        self.install_attestation_cert()

        cred = self.make_large_blob_key()

        assertion = self.get_assertion(rp_id=self.rp_id, extensions={"largeBlobKey": True})

        self.assertEqual(cred.large_blob_key, assertion.large_blob_key)

    def test_get_largeblobkey(self):
        cred = self.make_large_blob_key()

        assertion = self.get_assertion_from_cred(cred=cred, extensions={"largeBlobKey": True})

        self.assertEqual(cred.large_blob_key, assertion.large_blob_key)

    def test_iterative_largeblobkeys(self):
        creds = []
        for i in range(10):
            self.basic_makecred_params['user']['id'] = secrets.token_bytes(64)
            creds.append(self.make_large_blob_key())

        self.softResetCard()

        base_assertion = self.get_assertion(rp_id=self.rp_id, extensions={"largeBlobKey": True})
        self.assertEqual(len(creds), base_assertion.number_of_credentials)
        self.assertEqual(creds[-1].large_blob_key, base_assertion.large_blob_key)

        for i in range(len(creds) - 2, 0, -1):
            assertion = self.ctap2.get_next_assertion()
            self.assertEqual(creds[i].large_blob_key, assertion.large_blob_key)

    @parameterized.expand([
        ("mid", 100, 30, 40),
        ("start", 100, 0, 30),
        ("end", 100, 50, 50),
        ("long_mid", 800, 400, 150),
        ("long_nearend", 800, 600, 190),
        ("long_nearstart", 800, 20, 600),
    ])
    def test_ll_offset_read_of_largeblob(self, _, length, offset, read_len):
        blob_array = secrets.token_bytes(length)
        h = hashes.Hash(hashes.SHA256())
        h.update(blob_array)
        blob_array += h.finalize()[:16]

        self.ctap2.large_blobs(offset=0, set=blob_array, length=len(blob_array))
        res = self.ctap2.large_blobs(offset=offset, get=read_len)

        self.assertEqual(blob_array[offset:offset+read_len], res[1])

    def test_get_empty_largeblob_arr(self):
        arr = LargeBlobs(self.ctap2).read_blob_array()
        self.assertEqual(0, len(arr))

    @parameterized.expand([
        ("empty", 0),
        ("short", 10),
        ("onepacket", 200),
        ("onepacket2", 240),
        ("medium", 100),
        ("long", 600),
        ("chained", 950),
        ("maximal", 1004),
    ])
    def test_set_and_get_large_blobs(self, _, num_bytes):
        blob_array = [secrets.token_bytes(num_bytes)]
        LargeBlobs(self.ctap2).write_blob_array(blob_array)

        self.softResetCard()

        res = LargeBlobs(self.ctap2).read_blob_array()
        self.assertEqual(blob_array, res)

    def test_get_beyond_end(self):
        blob_array = secrets.token_bytes(54)
        h = hashes.Hash(hashes.SHA256())
        h.update(blob_array)
        blob_array += h.finalize()[:16]

        self.ctap2.large_blobs(offset=0, set=blob_array, length=len(blob_array))

        res = self.ctap2.large_blobs(offset=0, get=200)

        self.assertEqual(blob_array, res[1])

    def test_set_and_get_large_blobs_high_level(self):
        cred = self.make_large_blob_key()

        data = secrets.token_bytes(99)

        LargeBlobs(self.ctap2).put_blob(cred.large_blob_key, data=data)

        self.softResetCard()

        res = LargeBlobs(self.ctap2).get_blob(cred.large_blob_key)
        self.assertEqual(data, res)

    def test_mixing_blobs_from_different_keys(self):
        cred1 = self.make_large_blob_key()
        cred2 = self.make_large_blob_key()
        data1 = secrets.token_bytes(99)
        data2 = secrets.token_bytes(50)
        LargeBlobs(self.ctap2).put_blob(cred1.large_blob_key, data=data1)
        LargeBlobs(self.ctap2).put_blob(cred2.large_blob_key, data=data2)

        self.softResetCard()

        res2 = LargeBlobs(self.ctap2).get_blob(cred2.large_blob_key)
        res1 = LargeBlobs(self.ctap2).get_blob(cred1.large_blob_key)

        self.assertEqual(data1, res1)
        self.assertEqual(data2, res2)

    def test_overly_long_array_rejected(self):
        blob_array = [secrets.token_bytes(1005)]

        with self.assertRaises(CtapError) as e:
            LargeBlobs(self.ctap2).write_blob_array(blob_array)

        self.assertEqual(CtapError.ERR.LARGE_BLOB_STORAGE_FULL, e.exception.code)

    def test_largeblob_rejected_on_non_discoverable(self):
        client = self.get_high_level_client(extensions=[LargeBlobExtension])
        with self.assertRaises(ClientError) as e:
            client.make_credential(self.get_high_level_make_cred_options(
                extensions={
                    "largeBlob": {
                        "support": "required"
                    }
                }
            ))

        self.assertEqual(CtapError.ERR.INVALID_OPTION, e.exception.cause.code)

    def test_largeblob_ignored_when_not_requested(self):
        client = self.get_high_level_client(extensions=[LargeBlobExtension])

        cred = client.make_credential(self.get_high_level_make_cred_options(
            resident_key=ResidentKeyRequirement.REQUIRED
        ))

        self.assertEqual({}, cred.extension_results)


