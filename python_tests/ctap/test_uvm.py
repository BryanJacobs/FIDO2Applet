from typing import Optional, Any, Dict

from fido2.ctap2 import ClientPin, AssertionResponse, AttestationResponse
from fido2.ctap2.extensions import Ctap2Extension
from fido2.ctap2.pin import PinProtocol
from fido2.webauthn import UserVerificationRequirement

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class UVMExtension(Ctap2Extension):

    NAME = 'uvm'

    def is_supported(self) -> bool:
        return True

    def process_create_input(self, inputs: Dict[str, Any]) -> Any:
        return True

    def process_create_output(
        self,
        attestation_response: AttestationResponse,
        token: Optional[str],
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        return {
            "uvm": attestation_response.auth_data.extensions.get(self.NAME)
        }

    def process_get_input(self, inputs: Dict[str, Any]) -> Any:
        return True

    def process_get_output(
            self,
            assertion_response: AssertionResponse,
            token: Optional[str],
            pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        return {
            "uvm": assertion_response.auth_data.extensions.get(self.NAME)
        }


class UVMTestCase(CTAPTestCase):

    def test_uvm_no_pin_on_makecred(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params, extensions={
            "uvm": True
        })
        self.assertEqual([[1, 10, 4]], res.auth_data.extensions['uvm'])

    def test_uvm_with_pin_on_makecred(self):
        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension],
                                            user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(
            self.get_high_level_make_cred_options(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )

        self.assertEqual([[2048, 10, 4]], cred.extension_results['uvm'])

    def test_uvm_with_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options())

        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension],
                                            user_interaction=FixedPinUserInteraction(pin))

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred,
            user_verification=UserVerificationRequirement.REQUIRED
        ))

        self.assertEqual([[2048, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])

    def test_uvm_without_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options())

        client = self.get_high_level_client(extensions=[UVMExtension])

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred
        ))

        self.assertEqual([[1, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])
