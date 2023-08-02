from fido2.ctap import CtapError

from .ctap_test import CTAPTestCase


class CTAPMalformedInputTestCase(CTAPTestCase):

    def test_notices_invalid_keyparams_later_in_array(self):
        self.basic_makecred_params['key_params'].append({})
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.MISSING_PARAMETER, e.exception.code)

    def test_options_not_a_map(self):
        self.basic_makecred_params['options'] = []
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_extensions_not_a_map(self):
        self.basic_makecred_params['extensions'] = "Good and Loud"
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_rp_icon_not_text(self):
        self.basic_makecred_params['rp']['icon'] = 454
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_user_icon_not_text(self):
        self.basic_makecred_params['user']['icon'] = 454
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_rejects_non_string_type_in_array(self):
        self.basic_makecred_params['key_params'].append({
            "type": 3949,
            "alg": 12
        })
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_rejects_non_integer_alg_in_array(self):
        self.basic_makecred_params['key_params'].append({
            "type": "public-key",
            "alg": "foo"
        })
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)
