# FIDO2 CTAP2 Javacard Applet

## Overview

This repository contains sources for a FIDO2 CTAP2.1 compatible(-ish)
applet targeting the Javacard Classic system, version 3.0.4. In a
nutshell, this lets you take a smartcard, install an app onto it,
and have it work as a FIDO2 authenticator device with a variety of
features. You can generate and use OpenSSH `ecdsa-sk` type keys, including
ones you carry with you on the key (`-O resident`). You can securely unlock
a LUKS encrypted disk with `systemd-cryptenroll`. You can log in to a Linux
system locally with [pam-u2f](https://github.com/Yubico/pam-u2f).

This applet does **not** presently implement U2F support, for
[valid reasons](docs/FAQ.md). Note that `pam-u2f`, despite its name,
actually uses `libfido2` and will work fine.

In order to run this, you will need
[a compatible smartcard](docs/requirements.md). Some smartcards which
describe themselves as running Javacard 3.0.1 also work - see the
detailed requirements.

You might be interested in [reading about the security model](docs/security_model.md).

## Building the application

You'll need to get a copy of JavacardKit, version 3.0.4 (`jckit_304`):
you can build with jckit_303 if you prefer.

Set the environment variable `JC_HOME` to point to your jckit folder.

Run `./gradlew buildJavaCard`, which will produce a `.cap` file
for installation.

## Testing the application

While you can test on an actual smartcard, I prefer to use VSmartCard
and run JCardSim connected to that for ease and speed.

You can get great analysis of the applet's behaviour using real applications
or third-party testing suites like SoloKey's `fido2-tests`, which you can run
against the simulated application - the `VSim` class might get you started.

There are also a reasonable number of Python-language tests in the
`python_tests` top level directory. These start up JCardSim and use the
Python `python-fido2` library to interact the with applet. They're in Python
because, as of this writing, there is no FIDO2 client library available for
the JVM. And hey, interoperability testing, right? You can test with `libfido2`,
or Python libraries, or the official FIDO Standards Tests (Javascript). The
applet should pass everything you throw at it.

## Contributing

If you want to, feel free!

## Where to go Next

I suggest [reading the FAQ](docs/FAQ.md) and perhaps [the security model](docs/security_model.md).

## Implementation Status

| Feature                                   | Status                                                  |
|-------------------------------------------|---------------------------------------------------------|
| CTAP1/U2F                                 | Not implemented                                         |
| CTAP2.0 core                              | Implemented, many caveats                               |
| CTAP2.1 core                              | Implemented, many caveats                               |
| Resident keys                             | Implemented, default 50 slots                           |
| User Presence                             | User always considered present: not standards compliant |
| ECDSA (SecP256r1)                         | Implemented                                             |
| Self attestation                          | Implemented                                             |
| Basic attestation with ECDSA certs        | Implemented (see [install guide](docs/certs.md))        |
| Other crypto, like ed25519                | Not implemented                                         |
| CTAP2.0 hmac-secret extension             | Implemented                                             |
| CTAP2.1 hmac-secret extension             | Implemented                                             |
| CTAP2.1 alwaysUv option                   | Implemented                                             |
| CTAP2.1 credProtect option                | Implemented, one caveat                                 |
| CTAP2.1 PIN Protocol 1                    | Implemented                                             |
| CTAP2.1 PIN Protocol 2                    | Implemented                                             |
| CTAP2.1 credential management             | Implemented                                             |
| CTAP2.1 enterprise attestation            | Not implemented                                         |
| CTAP2.1 authenticator config              | Implemented (no settings modifiable)                    |
| CTAP2.1 credBlob extension                | Not implemented                                         |
| CTAP2.1 authenticatorLargeBlobs extension | Not implemented                                         |
| CTAP2.1 largeBlobKey extension            | Not implemented                                         |
| CTAP2.1 bio-stuff                         | Not implemented                                         |
| APDU chaining                             | Supported                                               |
| Extended APDUs                            | Supported                                               |
| Performance                               | Adequate (sub-3-second common operations)               |
| Resource consumption                      | Reasonably optimized for avoiding flash wear            |
| Bugs                                      | Yes                                                     |
| Code quality                              | No                                                      |
| Security                                  | Theoretical, but see "bugs" row above                   |

## Software Compatibility

| Platform              | Status   |
|-----------------------|----------|
| Android (hwsecurity)  | Working  |
| Android (Google Play) | Untested |
| iOS                   | Untested |
| Linux (libfido2)      | Working  |
| Windows 10            | Working  |

| Smartcard                  | Status  |
|----------------------------|---------|
| J3H145 (NXP JCOP3)         | Working |
| OMNI Ring (Infineon SLE78) | Working |
| jCardSim                   | Working |

Note that many of the applications below (cough, browsers)
support FIDO2 in theory but only allow USB security keys - this implementation
is for PC/SC, and doesn't implement USB HID, so it will only work with FIDO2
implementations that can handle e.g. NFC tokens instead of being restricted to USB.

| Application         | Status      |
|---------------------|-------------|
| Chrome on Android   | Untested    |
| Chrome on Linux     | Unsupported |
| Fennec on Android   | Unsupported |
| Firefox on Linux    | Unsupported |
| Firefox on Windows  | Working     |
| OpenSSH             | Working     |
| pam_u2f             | Working     |
| MS Edge             | Working     |
| Safari on iOS       | Untested    |
| systemd-cryptenroll | Working     |
| WebView on Android  | Working     |
