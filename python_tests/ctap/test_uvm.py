from typing import Optional, Any, Dict

from fido2.ctap2 import ClientPin, AssertionResponse, AttestationResponse, Ctap2
from fido2.ctap2.extensions import Ctap2Extension, AuthenticationExtensionProcessor, RegistrationExtensionProcessor
from fido2.ctap2.pin import PinProtocol
from fido2.webauthn import UserVerificationRequirement, PublicKeyCredentialRequestOptions, \
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class UVMAssertionProcessor(AuthenticationExtensionProcessor):
    def prepare_inputs(
        self,
        selected: PublicKeyCredentialDescriptor | None,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
        return {
            "uvm": True
        }

    def prepare_outputs(
        self,
        response: AssertionResponse,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
        return {
            "uvm": response.auth_data.extensions.get("uvm")
        }


class UVMRegistrationProcessor(RegistrationExtensionProcessor):
    def prepare_outputs(
        self,
        response: AttestationResponse,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
        return {
            "uvm": response.auth_data.extensions.get("uvm")
        }

    def prepare_inputs(self, pin_token: bytes | None) -> dict[str, Any] | None:
        return {
            "uvm": True
        }


class UVMExtension(Ctap2Extension):

    NAME = 'uvm'

    def is_supported(self, ctap: Ctap2) -> bool:
        return True

    def get_assertion(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialRequestOptions,
        pin_protocol: PinProtocol | None,
    ) -> AuthenticationExtensionProcessor | None:
        return UVMAssertionProcessor()

    def make_credential(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialCreationOptions,
        pin_protocol: PinProtocol | None,
    ) -> RegistrationExtensionProcessor | None:
        return UVMRegistrationProcessor()


class UVMTestCase(CTAPTestCase):

    def test_uvm_no_pin_on_makecred(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params, extensions={
            "uvm": True
        })
        self.assertEqual([[1, 10, 4]], res.auth_data.extensions['uvm'])

    def test_uvm_with_pin_on_makecred(self):
        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension()],
                                            user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(
            self.get_high_level_make_cred_options(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )

        self.assertEqual([[2048, 10, 4]], cred.client_extension_results['uvm'])

    def test_uvm_with_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options()).response

        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension()],
                                            user_interaction=FixedPinUserInteraction(pin))

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred,
            user_verification=UserVerificationRequirement.REQUIRED
        ))

        self.assertEqual([[2048, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])

    def test_uvm_without_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options()).response

        client = self.get_high_level_client(extensions=[UVMExtension()])

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred
        ))

        self.assertEqual([[1, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])
