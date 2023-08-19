# Installing the Applet for Basic Attestation

A default install of the FIDO2Applet will use "self attestation". This prevents any
CTAP1/U2F functionality (U2F requires attestation certificates). The authenticator will
have a CTAP2 AAGUID of all zeros.

If you instead wish to use CTAP2 Basic Attestation and/or CTAP1, you will need to provide
an AAGUID, a certificate chain, and a private key before using the applet. Only P256
certificates (ECDSA) are supported for the authenticator's own certificate; any algorithm
may be used for CAs further up the chain.

These may be provided via a vendor CTAP command (command byte 0x46). In order
to enable the vendor CTAP command, you must install the applet with parameters enabling it:
see [the install guide](installation.md).

The vendor CTAP command will be rejected if the authenticator already contains a certificate,
or if the authenticator has been used to make any credentials since the last reset, so it must
be installed FIRST. Note that the AAGUID and certificate are not cleared by resetting the
authenticator; once installed, they persist until the applet is deleted, and cannot be changed.

The syntax for the data to the vendor command is as follows:

1. 16 byte AAGUID
1. 32 byte ECDSA private key point (aka the S-value)
1. Two-byte total length of CBOR object following this one
1. Remaining bytes are a CBOR-encoded array of certificates, with each cert encoded as DER. The
   first certificate in the array must correspond to the authenticator's own key. Note that this
   MUST be a CBOR array even if it contains only one element!

Notes on length:
- You'll be using APDU chaining, so the maximum total size is a hair under 65535 bytes
- Certificates will be stored directly into an on-flash byte array, so the maximum is also
  limited by the available flash
- Keep the first certificate to a few hundred bytes or U2F/CTAP1 registration requests will fail:
  the device only has a 1024 byte transmission buffer

Advice: keep your certificates *as short as possible*, since the longer they are, the more
flash you'll use and the slower the makeCredential/register operations will be.

You can install a self-signed certificate easily using the `install_attestation_cert.py` script in
the repository root.
