import os
import random
import secrets
from multiprocessing import Queue, Process
from typing import ClassVar, Optional, Any, Type
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from fido2.client import UserInteraction, Fido2Client
from fido2.cose import ES256
from fido2.ctap2 import Ctap2, ClientPin, AttestationResponse, AssertionResponse
from fido2.ctap2.extensions import Ctap2Extension
from fido2.pcsc import CtapPcscDevice
from fido2.webauthn import ResidentKeyRequirement, PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, \
    PublicKeyCredentialRpEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, AuthenticatorSelectionCriteria, \
    UserVerificationRequirement, PublicKeyCredentialDescriptor, AuthenticatorAttestationResponse, \
    PublicKeyCredentialRequestOptions


class JCardSimTestCase(TestCase):

    q_in: ClassVar[Queue]
    q_out: ClassVar[Queue]
    p: ClassVar[Process]

    DEBUG_PORT = 5005
    SUSPEND_ON_LAUNCH = False

    @classmethod
    def start_jvm(cls):
        import jpype.imports

        my_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        path_to_jars = os.path.join(my_path, 'build', 'libs')
        jars = os.listdir(path_to_jars)
        main_jars = []
        test_jars = []
        for jar in jars:
            if jar.startswith('fido2applet-tests-'):
                test_jars.append(jar)
            elif jar.startswith('fido2applet-'):
                main_jars.append(jar)
        if len(main_jars) == 0:
            raise ValueError("Applet not built - run ./gradlew jar")
        elif len(main_jars) > 1:
            raise ValueError("More than one main jar in build/libs - remove all but one")
        if len(test_jars) == 0:
            raise ValueError("Tests not built - run ./gradlew testJar")
        elif len(test_jars) > 1:
            raise ValueError("More than one test jar in build/libs - remove all but one")

        jc_home = os.environ.get("JC_HOME")
        if not jc_home:
            raise ValueError("$JC_HOME must be set to the path of your JavacardKit")
        jc_jars = os.path.join(jc_home, 'lib')

        classpath = [
            os.path.abspath(os.path.join(path_to_jars, main_jars[0])),  # Applet jar
            os.path.abspath(os.path.join(path_to_jars, test_jars[0])),  # Test support jar
        ]
        classpath += [
            os.path.join(jc_jars, x) for x in os.listdir(jc_jars)
        ]

        suspend_char = 'y' if cls.SUSPEND_ON_LAUNCH else 'n'

        jpype.startJVM(
            "-agentlib:jdwp=transport=dt_socket,server=y,"
            f"suspend={suspend_char},address={cls.DEBUG_PORT}",
            classpath=classpath
        )

    @classmethod
    def launch_sim(cls, incoming_q: Queue, outgoing_q: Queue):
        cls.start_jvm()
        from us.q3q.fido2 import VSim

        sim = VSim.startBackgroundSimulator()
        VSim.installApplet(sim, bytes())
        while True:
            applet_install_params = incoming_q.get(block=True)
            if applet_install_params is None:
                # We're done - exit
                break
            # Reset the simulator to fresh
            sim.resetRuntime()
            sim.reset()
            VSim.installApplet(sim, applet_install_params)
            outgoing_q.put(None, block=True)

    @classmethod
    def setUpClass(cls) -> None:
        cls.q_in = Queue()
        cls.q_out = Queue()
        cls.p = Process(target=cls.launch_sim, args=(cls.q_out, cls.q_in))
        cls.p.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.p.kill()
        cls.p.join()

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        if install_params is None:
            install_params = bytes()
        # Javacard install parameters are prefixed by AID and platform info
        ip_len = len(install_params)
        install_params = bytes([1, 95, 1, 86, ip_len]) + install_params
        self.q_out.put(install_params)  # Tell JVM to reset applet state
        self.q_in.get(block=True)  # Wait for applet to be started in JVM


class CTAPTestCase(JCardSimTestCase):
    VIRTUAL_DEVICE_NAME = "Virtual PCD"
    device: CtapPcscDevice
    ctap2: Ctap2
    client_data: bytes
    rp_id: str
    basic_makecred_params: dict[str, Any]

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        self.basic_makecred_params = {
            "rp": {},
            "user": {},
            "key_params": [
                {
                    "type": "public-key",
                    "alg": ES256.ALGORITHM
                }
            ],
        }
        if install_params is None:
            install_params = bytes([0x01])
        super().setUp(install_params)
        devs = list(CtapPcscDevice.list_devices(self.VIRTUAL_DEVICE_NAME))
        assert 1 == len(devs)
        self.device = devs[0]
        self.ctap2 = Ctap2(self.device)

        self.client_data = self.get_random_client_data()
        self.basic_makecred_params["client_data_hash"] = self.client_data
        rpid_length = random.randint(1, 16)
        self.rp_id = secrets.token_hex(rpid_length)
        self.basic_makecred_params['rp']['id'] = self.rp_id
        userid_length = random.randint(1, 64)
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(userid_length)

    @classmethod
    def get_random_client_data(cls) -> bytes:
        return secrets.token_bytes(32)

    def get_assertion_from_cred(self, cred_res: AttestationResponse,
                                rp_id: Optional[str] = None,
                                client_data: Optional[bytes] = None) -> AssertionResponse:
        if rp_id is None:
            rp_id = self.rp_id
        if client_data is None:
            client_data = self.client_data
        return self.ctap2.get_assertion(
            rp_id=rp_id,
            client_data_hash=client_data,
            allow_list=[
                {
                    "type": "public-key",
                    "id": cred_res.auth_data.credential_data.credential_id
                }
            ]
        )

    def get_high_level_client(self, extensions: Optional[list[Type[Ctap2Extension]]] = None,
                              user_interaction: UserInteraction = None,
                              origin: str = None) -> Fido2Client:
        if extensions is None:
            extensions = []
        if user_interaction is None:
            user_interaction = UserInteraction()
        if origin is None:
            origin = 'https://' + self.rp_id
        return Fido2Client(self.device, origin=origin,
                           extension_types=extensions, user_interaction=user_interaction)

    def get_high_level_make_cred_options(self,
                                         resident_key: ResidentKeyRequirement = ResidentKeyRequirement.DISCOURAGED,
                                         extensions=None, rp_id: Optional[str] = None,
                                         user_id: Optional[bytes] = None) -> PublicKeyCredentialCreationOptions:
        if extensions is None:
            extensions = {}

        if rp_id is None:
            rp_id = self.rp_id

        if user_id is None:
            user_id = self.basic_makecred_params['user']['id']

        return PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(
                name="An RP Name",
                id=rp_id
            ),
            user=PublicKeyCredentialUserEntity(
                name="Bob",
                id=user_id
            ),
            challenge=self.client_data,
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=ES256.ALGORITHM
                )
            ],
            extensions=extensions,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=resident_key,
                user_verification=UserVerificationRequirement.DISCOURAGED
            )
        )

    def get_high_level_assertion_opts_from_cred(self, cred: Optional[AuthenticatorAttestationResponse] = None,
                                                client_data: Optional[bytes] = None, rp_id: Optional[str] = None,
                                                extensions: Optional[
                                                    dict[str, Any]] = None) -> PublicKeyCredentialRequestOptions:
        if extensions is None:
            extensions = {}
        if client_data is None:
            client_data = self.client_data
        if rp_id is None:
            rp_id = self.rp_id
        assertion_allow_credentials = []
        if cred is not None:
            assertion_allow_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred.attestation_object.auth_data.credential_data.credential_id
                )
            ]
        return PublicKeyCredentialRequestOptions(
            challenge=client_data,
            rp_id=rp_id,
            allow_credentials=assertion_allow_credentials,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            extensions=extensions
        )


class BasicAttestationTestCase(CTAPTestCase):
    public_key: EllipticCurvePublicKey
    aaguid: bytes
    cert: bytes

    def _short_to_bytes(self, b: int) -> list[int]:
        return [(b & 0xFF00) >> 8, b & 0x00FF]

    def gen_attestation_cert(self, cert_data: Optional[bytes] = None) -> bytes:
        self.aaguid = secrets.token_bytes(16)

        private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = private_key.public_key()

        if cert_data is None:
            cert_len = random.randint(1, 14)
            cert_data = secrets.token_bytes(cert_len)
        else:
            cert_len = len(cert_data)

        self.cert = cert_data
        if cert_len <= 23:
            cert_len_cbor = [0x40 + cert_len]
        elif cert_len <= 255:
            cert_len_cbor = [0x58, cert_len]
        elif cert_len <= 65535:
            cert_len_cbor = [0x59] + self._short_to_bytes(cert_len)
        else:
            raise NotImplementedError()
        cert_cbor = bytes([0x81] + cert_len_cbor) + self.cert

        s = private_key.private_numbers().private_value
        private_bytes = s.to_bytes(length=32)
        self.assertEqual(32, len(private_bytes))
        cbor_len_bytes = bytes(self._short_to_bytes(len(cert_cbor)))
        res = self.aaguid + private_bytes + cbor_len_bytes + cert_cbor
        self.assertEqual(16 + 32 + cert_len + len(cert_len_cbor) + 3, len(res))
        return res


class FixedPinUserInteraction(UserInteraction):
    pin: str

    def __init__(self, pin: str):
        self.pin = pin

    def request_pin(
            self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> Optional[str]:
        return self.pin

