#!/usr/bin/env python

import sys
import argparse
import base64

from fido2.ctap2 import Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.pcsc import CtapPcscDevice

import secrets

from cryptography.hazmat.primitives.asymmetric import ec

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
                        help='CA private key, expressed as a hex string')
    parser.add_argument('--org',
                        default='ACME',
                        help='Organization name to use for certificates')
    parser.add_argument('--country',
                        default='US',
                        help='ISO country code to use for certificates')
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
    else:
        ca_privkey_and_cert = bytes.fromhex(args.ca_private_key), base64.b64decode(args.ca_cert_bytes)
    private_key = ec.generate_private_key(ec.SECP256R1())

    cert_bytes = tc.get_x509_certs(private_key, name=args.name, ca_privkey_and_cert=ca_privkey_and_cert,
                                   org=args.org, country=args.country)
    print(f"Using AAGUID: {aaguid.hex()}")
    print(f"Using CA certificate: {base64.b64encode(cert_bytes[-1])}")

    at_bytes = tc.assemble_cbor_from_attestation_certs(private_key=private_key,
                                                       cert_bytes=cert_bytes,
                                                       aaguid=aaguid)

    devices = list(CtapPcscDevice.list_devices())
    if len(devices) > 1:
        sys.stderr.write("Found multiple PC/SC devices!\n")
        sys.exit(1)
    if len(devices) == 0:
        sys.stderr.write("Could not find any FIDO PC/SC devices!\n")
        sys.exit(1)
    device = devices[0]

    res = Ctap2(device).send_cbor(
        0x46,
        ctap_args(at_bytes)
    )
    print(f"Got response: {res} (empty is good)")
