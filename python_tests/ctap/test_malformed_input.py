from fido2.ctap import CtapError

from .ctap_test import CTAPTestCase


class CTAPMalformedInputTestCase(CTAPTestCase):

    def test_notices_invalid_keyparams_later_in_array(self):
        self.basic_makecred_params['key_params'].append({})
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.MISSING_PARAMETER, e.exception.code)
