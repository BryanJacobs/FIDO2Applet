#!/usr/bin/env python

import sys
import argparse
import base64
import binascii

from fido2.ctap2 import Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.pcsc import CtapPcscDevice

import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_der_private_key

from python_tests.ctap.ctap_test import BasicAttestationTestCase

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Install AAGUID and attestation certificate(s)')
    parser.add_argument('--name',
                        default='FIDO2Applet',
                        help='Common name to use for the certificate')
    parser.add_argument('--aaguid',
                        default=None,
                        help='AAGUID to use, expressed as 16 hex bytes (32-character-long string)')
    parser.add_argument('--ca-cert-bytes',
                        default=None,
                        help='CA certificate, expressed as base64-encoded DER')
    parser.add_argument('--ca-private-key',
                        default=None,
                        help='CA private key, expressed as base64-encoded unencrypted PKCS8 DER')
    parser.add_argument('--org',
                        default='ACME',
                        help='Organization name to use for certificates')
    parser.add_argument('--country',
                        default='US',
                        help='ISO country code to use for certificates')
    parser.add_argument('--already-loaded-public-key',
                        help='The private key is already loaded on the card; this is the base64 DER-encoded PUBLIC key')
    args = parser.parse_args()

    if (args.ca_private_key is None) != (args.ca_cert_bytes is None):
        raise IllegalArgumentException("Either both or neither of CA certificate and private key must be set")

    aaguid = None
    if args.aaguid is not None:
        if len(args.aaguid) != 32:
            sys.stderr.write("Invalid AAGUID length!\n")
            sys.exit(1)
        aaguid = bytes.fromhex(args.aaguid)
    else:
        aaguid = secrets.token_bytes(16)

    tc = BasicAttestationTestCase()
    if args.ca_private_key is None:
        ca_privkey_and_cert = tc.get_ca_cert(org=args.org)
        privkey_bytes = ca_privkey_and_cert[0].private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        print(f"Generated CA private key: {base64.b64encode(privkey_bytes)}")
        print(f"Generated CA cert: {base64.b64encode(ca_privkey_and_cert[1])}")
    else:
        privkey = load_der_private_key(data=base64.b64decode(args.ca_private_key), password=None)
        ca_privkey_and_cert = privkey, base64.b64decode(args.ca_cert_bytes)

    print(f"Using AAGUID: {aaguid.hex()}")

    get_certs_args = {
        "name": args.name,
        "ca_privkey_and_cert": ca_privkey_and_cert,
        "org": args.org,
        "country": args.country
    }

    if args.already_loaded_public_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        get_certs_args['private_key'] = private_key
    else:
        private_key = None
        public_key = base64.b64decode(args.already_loaded_public_key)
        get_certs_args['public_key'] = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            public_key
        )
        print("Using existing public key " + str(binascii.hexlify(public_key)))
    cert_bytes = tc.get_x509_certs(**get_certs_args)

    at_bytes = tc.assemble_cbor_from_attestation_certs(private_key=private_key,
                                                       cert_bytes=cert_bytes[:-1],
                                                       aaguid=aaguid)

    print(binascii.hexlify(at_bytes))

    devices = list(CtapPcscDevice.list_devices())
    if len(devices) > 1:
        sys.stderr.write("Found multiple PC/SC devices!\n")
        sys.exit(1)
    if len(devices) == 0:
        sys.stderr.write("Could not find any usable FIDO PC/SC devices! Make sure your user account can read/write to pcscd...\n")
        sys.exit(1)
    device = devices[0]

    res = Ctap2(device).send_cbor(
        0x46,
        ctap_args(at_bytes)
    )
    print(f"Got response: {res} (empty is good)")
