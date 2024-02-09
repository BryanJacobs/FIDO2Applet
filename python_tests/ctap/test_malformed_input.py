import secrets

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin

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

    def test_too_many_extensions(self):
        d = {}
        for x in range(30):
            d[str(x)] = True
        self.basic_makecred_params['extensions'] = d
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

    def test_bogus_makecred_options(self):
        self.basic_makecred_params['options'] = {'frobble': 23}
        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_bogus_getassert_options(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        self.get_assertion_from_cred(cred, options={'bogus': 123})

    def test_bogus_exclude_list(self):
        self.basic_makecred_params['exclude_list'] = 12345

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_bogus_exclude_list_entry(self):
        self.basic_makecred_params['exclude_list'] = [12345]

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_exclude_list_not_array_raw(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("01a501582087e85f1f2eb615568b93d528574858f21d4cdbd6c0389fffe8d83977fc52d11102a26269646f73717565616d6973686669672e666d646e616d657829546865204578616d706c6520436f72706f726174696f6e20776974682066616b6520646f6d61696e2103a3626964582049aad568d2165c8d1ae1f9feb29bdbeef0e7305ec7e0dd5c811e67a0654d820a646e616d657818616c656370616c617a7a6f40657874656e6479616d2e63666b646973706c61794e616d656c416c65632050616c617a7a6f0481a263616c672664747970656a7075626c69632d6b65790574616c444346775f3976626f6b336b56462d497348"))

        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, res[0])

    def test_empty_pinuvauth_with_create(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("01A5015820FDA53DBE83484DC63BE566B024696E84FE0E24B219535EB98514D883481C5E5402A1626964781834316165343262633166623338343132386561333566646403A3626964583DBDEA92D4DAFD424B45B3DCE17BF6B8F65632D20D6CAF844BA92FE5CA44EFEDCF6A25059BF7AFB20AB2EBA99FF8D35A8EF0460D7233918505CA4998CA06646E616D656E38656536313763656133636464366C646973706C61795F6E616D65782632336362626239363038326665316439623738623734306235653735326133306334633130640481A263616C672664747970656A7075626C69632D6B65790840"))

        self.assertEqual(CtapError.ERR.PIN_NOT_SET, res[0])

    def test_empty_pinuvauth_with_assert(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("02A4017820373766633733386666343537623033333337626266336538646264326237376202582001CAA8FE3488889C87E083EF22561A38C724D558646DEFB9B3C8D923F959D54C0381A26269645870EDEFB6C58327538F3B4F7E4B9AF30C70DDEE6C548FA0BEA66C59567CE8CD048258C27FB46EECCB66A23E208AF23A4D3C2E9E78B1CB53BE87419E1D0DAD2C584F84513502486B9791E3949BE75CA0F05789B37758300BD66E933317595AFFEDDB2C1762C0DC7504743B95371411787F0164747970656A7075626C69632D6B65790640"))

        self.assertEqual(CtapError.ERR.PIN_NOT_SET, res[0])

    def test_empty_pinuvauth_with_create_pin(self):
        cp = ClientPin(self.ctap2)
        cp.set_pin('aaaaaa')
        res = self.ctap2.device.call(0x10, bytes.fromhex("01A5015820FDA53DBE83484DC63BE566B024696E84FE0E24B219535EB98514D883481C5E5402A1626964781834316165343262633166623338343132386561333566646403A3626964583DBDEA92D4DAFD424B45B3DCE17BF6B8F65632D20D6CAF844BA92FE5CA44EFEDCF6A25059BF7AFB20AB2EBA99FF8D35A8EF0460D7233918505CA4998CA06646E616D656E38656536313763656133636464366C646973706C61795F6E616D65782632336362626239363038326665316439623738623734306235653735326133306334633130640481A263616C672664747970656A7075626C69632D6B65790840"))

        self.assertEqual(CtapError.ERR.PIN_INVALID, res[0])

    def test_empty_pinuvauth_with_assert_pin(self):
        cp = ClientPin(self.ctap2)
        cp.set_pin('aaaaaa')

        res = self.ctap2.device.call(0x10, bytes.fromhex("02A4017820373766633733386666343537623033333337626266336538646264326237376202582001CAA8FE3488889C87E083EF22561A38C724D558646DEFB9B3C8D923F959D54C0381A26269645870EDEFB6C58327538F3B4F7E4B9AF30C70DDEE6C548FA0BEA66C59567CE8CD048258C27FB46EECCB66A23E208AF23A4D3C2E9E78B1CB53BE87419E1D0DAD2C584F84513502486B9791E3949BE75CA0F05789B37758300BD66E933317595AFFEDDB2C1762C0DC7504743B95371411787F0164747970656A7075626C69632D6B65790640"))

        self.assertEqual(CtapError.ERR.PIN_INVALID, res[0])

    def test_options_not_map_raw(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("01a501582078983526ab67de0cb8bca9996d14a83b248ddcfb586f18fd815ba953d19f618a02a26269646e73617473756d61686f6f6b2e6172646e616d657829546865204578616d706c6520436f72706f726174696f6e20776974682066616b6520646f6d61696e2103a362696458209d95b802bd88ef691b1b8f6cc00c258dc56be2ca80f3027b449415499e498e2c646e616d65782a636872697374656e61796f7368696d75726140696e6475737472696f7573626c75652d657965642e70746b646973706c61794e616d6573436872697374656e6120596f7368696d7572610481a263616c672664747970656a7075626c69632d6b65790680"))
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, res[0])

    def test_invalid_pubkeycredparams_seq_raw(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("01a401582088ebea80f87453c4981821b9ef5a2017da4dee5c09454b5be5ef6bb0b5e59bab02a26269647673746172667275697477686973706572696e672e7669646e616d657829546865204578616d706c6520436f72706f726174696f6e20776974682066616b6520646f6d61696e2103a36269645820c3d2bd8894cfadb71278ac4ed0fe5c1c46ae949495b7261b3d685cab52eaf090646e616d65781d746172656e2e67617465776f6f644072656a6f696365777261702e706d6b646973706c61794e616d656e546172656e2047617465776f6f640482a263616c672664747970656a7075626c69632d6b65797450755a5f6b6e4a584269646d4b796970344c7552"))
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, res[0])

    def test_bogus_exclude_list_entry_after_valid(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params, exclude_list=[
                self.get_descriptor_from_ll_cred(cred),
                12334
            ])

        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_user_icon_not_text(self):
        self.basic_makecred_params['user']['icon'] = secrets.token_bytes(16)

        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)

    def test_user_id_only(self):
        self.basic_makecred_params['user'] = {"id": self.basic_makecred_params['user']["id"]}

        cred = self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertIsNotNone(cred)

    def test_rp_icon_not_text(self):
        self.basic_makecred_params['rp']['icon'] = secrets.token_bytes(16)

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

    def test_rejects_es256_with_non_string_type(self):
        self.basic_makecred_params['key_params'].append({
            "type": False,
            "alg": -7
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

    def test_rejects_non_integer_alg_at_start_of_array(self):
        self.basic_makecred_params['key_params'].insert(0, {
            "type": "public-key",
            "alg": "foo"
        })
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, e.exception.code)
