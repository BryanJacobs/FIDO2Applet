#!/usr/bin/env python

import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives import serialization

if __name__ == '__main__':
    privkey = ec.generate_private_key(ec.SECP256R1())
    pubkey = privkey.public_key()

    private_bytes = privkey.private_numbers().private_value.to_bytes(length=32, byteorder='big')
    public_bytes = pubkey.public_bytes(encoding=Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

    print("PRIVATE key: " + str(base64.b64encode(private_bytes)))
    print("PUBLIC key: " + str(base64.b64encode(public_bytes)))
