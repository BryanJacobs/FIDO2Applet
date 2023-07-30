# Installing the Applet for Basic Attestation

A default install of the FIDO2Applet will use "self attestation". This disables any
CTAP1/U2F functionality (U2F requires attestation certificates). The authenticator will
have a CTAP2 AAGUID of all zeros.

If you instead wish to use CTAP2 Basic Attestation and/or CTAP1, you will need to provide
an AAGUID, a certificate chain, and a private key before using the applet. Only P256
certificates (ECDSA) are supported for the authenticator's own certificate; any algorithm
may be used for CAs further up the chain.

These may be provided via Applet install parameters, although the maximum length in that case
is a very restrictive 255 bytes, or via a vendor CTAP command (command byte 0x46). In order
to enable the vendor CTAP command, you must provide an install parameter of a single byte,
`0x01`. By default, the vendor command will be rejected to avoid inadvertently allowing an attacker
to switch the authenticator to basic attestation mode.

The vendor CTAP command will be rejected if the authenticator already contains a certificate,
or if the authenticator has been used to make any credentials since the last reset, so it must
be installed FIRST. Note that the AAGUID and certificate are not cleared by resetting the
authenticator; once installed, they persist until the applet is deleted, and cannot be changed.

The syntax for the parameters, whether provided at install time or as data to the vendor command,
is as follows:

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
