# FIDO2 CTAP2 Javacard Applet

## Overview

This repository contains sources for a feature-rich, FIDO2 CTAP2.1
compatible applet targeting the Javacard Classic system, version 3.0.4. In a
nutshell, this lets you take a smartcard, install an app onto it,
and have it work as a FIDO2 authenticator device with a variety of
features. You can generate and use OpenSSH `ecdsa-sk` type keys, including
ones you carry with you on the key (`-O resident`). You can securely unlock
a LUKS encrypted disk with `systemd-cryptenroll`. You can log in to a Linux
system locally with [pam-u2f](https://github.com/Yubico/pam-u2f).

100% of the FIDO2 CTAP2.1 spec is covered, with the exception of features
that aren't physically on an ordinary smartcard, such as biometrics or
other on-board user verification. The implementation in the default configuration
passes the official FIDO certification test suite version 1.7.17 in
"CTAP2.1 full feature profile" mode. Some CTAP 2.2+ features are also supported.

In order to run this outside a simulator, you will need
[a compatible smartcard](docs/requirements.md). Some smartcards which
describe themselves as running Javacard 3.0.1 also work - see the
detailed requirements.

You might be interested in [reading about the security model](docs/security_model.md).

## Environment setup and building the application

1. Configure the `JC_HOME` environment variable to point to a JavacardKit directory (optionally from the `sdks` submodule of this repository).
   ```bash
   export JC_HOME=<path_to_your_jckit_directory>
   ```

2. Build the JavaCard application, producing a `.cap` file for installation in `build/javacard`.
    ```bash
   ./gradlew buildJavaCard
    ```


## Testing the Application

### Overview
You have multiple options for testing the JavaCard application:

1. **Actual Smartcard**: You can test on a physical smartcard.
2. **Virtual SmartCard**: You can use VSmartCard and JCardSim for quicker and easier testing.

### Detailed Steps for Virtual Testing

When running through VSmartCard and JCardSim, you can use
tools like SoloKey's `fido2-tests` or other test suites.
The `VSim` class in this repository might help you get started.

#### Python Tests

Navigate to the `python_tests` directory, which contains Python-language tests, and:

   ```bash
   export JC_HOME=<your_jckit>
   ./gradlew jar testJar
   python -m venv venv
   ./venv/bin/pip install -U -r requirements.txt
   ./venv/bin/python -m unittest discover -s python_tests
   ```

These tests use the Python `python-fido2` library because there 
was, before FIDOk at the time this app was written, no FIDO2 client library
for the JVM. You can also test with `libfido2`, Python libraries, or the
official FIDO Standards Tests (Javascript).

By default, the Python tests use fast interprocess communication with the JVM,
bypassing PC/SC. The tests take less than thirty seconds to run, for me, even
though there are almost two hundred cases.

#### Advanced Settings

You can modify settings in `python_tests/ctap/ctap_test.py` to enable CTAP traffic logging,
allow JVM remote debugging, or use a VSmartCard PC/SC connection instead of the default IPC.


## Contributing

If you wish to contribute to the project, feel free to raise a pull request or open an issue.

## Where to go Next

If you just want to install the app, look at [what you can configure](docs/installation.md).

I suggest [reading the FAQ](docs/FAQ.md) and perhaps [the security model](docs/security_model.md).

If you're a really detail-oriented person, you might enjoy reading
[about the implementation](docs/implementation.md).

## Implementation Status

| Feature                             | Status                                                |
|-------------------------------------|-------------------------------------------------------|
| CTAP1/U2F                           | Implemented (see [install guide](docs/certs.md))      |
| CTAP2.0 core                        | Implemented                                           |
| CTAP2.1 core                        | Implemented                                           |
| Resident keys / Discoverable creds  | Implemented                                           |
| User Presence                       | User always considered present: one verification only |
| ECDSA (SecP256r1)                   | Implemented                                           |
| Other crypto, like ed25519          | Not implemented - availability depends on hardware    |
| Self attestation                    | Implemented                                           |
| Basic attestation with ECDSA certs  | Implemented (see [install guide](docs/certs.md))      |
| Webauthn (NOT CTAP!) uvm extension  | Implemented                                           |
| Webauthn devicePubKey extension     | Not implemented                                       |
| CTAP2.1 hmac-secret extension       | Implemented                                           |
| CTAP2.2 hmac-secret-mc extension    | Not implemented                                       |
| CTAP2.1 alwaysUv option             | Implemented                                           |
| CTAP2.1 credProtect option          | Implemented                                           |
| CTAP2.1 PIN Protocol 1              | Implemented                                           |
| CTAP2.1 PIN Protocol 2              | Implemented                                           |
| CTAP2.1 credential management       | Implemented                                           |
| CTAP2.1 enterprise attestation      | Implemented in code, disabled                         |
| CTAP2.1 PIN complexity policies     | Not implemented (min length is supported though)      |
| CTAP2.1 authenticator config        | Implemented                                           |
| CTAP2.1 minPinLength extension      | Implemented, default max two RPIDs can receive        |
| CTAP2.1 credBlob extension          | Implemented, discoverable creds only                  |
| CTAP2.1 largeBlobKey extension      | Implemented                                           |
| CTAP2.1 authenticatorLargeBlobs     | Implemented, default 1024 bytes storage (max 4k)      |
| CTAP2.1 bio-stuff                   | Not implemented (doesn't make sense in this context?) |
| CTAP2.2 thirdPartyPayment extension | Not implemented                                       |
| CTAP2.2 persistent UV token         | Not implemented                                       |
| CTAP2.2 encIdentifier               | Not implemented                                       |
| CTAP2.2 uvCountSinceLastPinEntry    | Not implemented                                       |
| CTAP2.3 long touch for reset        | Not implemented (doesn't make sense in this context)  |
| CTAP2.2/2.3 hybrid authenticator    | Not implemented (doesn't make sense in this context)  |
| Key backups                         | Not implemented                                       |
| APDU chaining                       | Supported                                             |
| Extended APDUs                      | Supported                                             |
| Performance                         | Adequate (sub-3-second common operations)             |
| Resource consumption                | Reasonably optimized for avoiding flash wear          |
| Bugs                                | Probably? Many have been fixed. Appears to work OK.   |
| Code quality                        | No                                                    |
| Security                            | Theoretical, but see "bugs" row above                 |

## Software Compatibility

| Platform                  | Status           |
|---------------------------|------------------|
| Android (Google Play)     | CTAP1 only [1]   |
| Android (hwsecurity)      | Working          |
| Android (MicroG)          | Working          |
| Android (FIDOk)           | Working          |
| iOS                       | Reported working |
| Linux (libfido2)          | Working          |
| Linux (FIDOk)             | Working          |
| Windows 10                | Working          |

| Smartcard                                                                         | Status           |
|-----------------------------------------------------------------------------------|------------------|
| J3H145 (NXP JCOP3)                                                                | Working          |
| J3R180 (NXP JCOP4)                                                                | Working          |
| OMNI Ring (Infineon SLE78)                                                        | Working          |
| jCardSim                                                                          | Working          |
| [Vivokey FlexSecure (NXP JCOP4)](https://dangerousthings.com/product/flexsecure/) | Working          |
| A40CR                                                                             | Reported Working |

| Application         | Status                         |
|---------------------|--------------------------------|
| Chrome on Android   | CTAP1 Only (Play Services [1]) |
| Chrome on Linux     | Working, USBHID only [2]       |
| Chrome on Windows   | Working                        |
| Fennec on Android   | CTAP1 Only (Play Services [1]) |
| WebView on Android  | Working                        |
| Firefox on Linux    | Working, USBHID only [2]       |
| Firefox on Windows  | Working                        |
| MS Edge on Windows  | Working                        |
| Safari on iOS       | Reported working               |
| OpenSSH             | Working                        |
| pam_u2f             | Working                        |
| systemd-cryptenroll | Working                        |
| python-fido2        | Working                        |
| FIDOk               | Working                        |

There are two compatibility issues in the table above:
1. Google Play Services on Android contains a complete webauthn implementation, but it appears to be
   hardwired to use only "passkeys". If a site explicitly requests a *non-discoverable* credential,
   you will be prompted to use an NFC security key, but this is only CTAP1 and not CTAP2. There's
   nothing fundamentally preventing this from working on Android but the current state of Chrome
   and Fennec are that CTAP2 doesn't, because both use the broken Play Services library. MicroG has
   a fully-working implementation, though! See https://github.com/microg/GmsCore/pull/2194 for PIN
   support.
1. Some browsers support FIDO2 in theory but only allow USB security keys - this implementation
   is for PC/SC, and doesn't implement USB HID, so it will only work with FIDO2
   implementations that can handle e.g. NFC tokens instead of being restricted to USB.
   In order to use a smartcard in these situations you'll need https://github.com/StarGate01/CTAP-bridge ,
   https://github.com/BryanJacobs/fido2-hid-bridge/ , https://github.com/BryanJacobs/FIDOk/ or similar,
   bridging USB-HID traffic to PC/SC.
