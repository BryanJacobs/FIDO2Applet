#!/usr/bin/env python

import sys
import argparse

from fido2.ctap2 import Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.pcsc import CtapPcscDevice

from python_tests.ctap.ctap_test import BasicAttestationTestCase

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Install AAGUID and attestation certificate(s)')
    parser.add_argument('--name',
                        default='FIDO2Applet',
                        help='Common name to use for the certificate')
    parser.add_argument('--aaguid',
                        default=None,
                        help='AAGUID to use, expressed as 16 hex bytes (32-character-long string)')
    args = parser.parse_args()

    aaguid = None
    if args.aaguid is not None:
        if len(args.aaguid) != 32:
            sys.stderr.write("Invalid AAGUID length!\n")
            sys.exit(1)
        aaguid = bytes.fromhex(args.aaguid)

    tc = BasicAttestationTestCase()
    at_bytes = tc.gen_attestation_cert(name=args.name, aaguid=aaguid)

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
    print(f"Got response: {res}")
