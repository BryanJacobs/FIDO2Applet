# FIDO2 CTAP2 Javacard Applet

## Overview

This repository contains sources for a feature complete, FIDO2 CTAP2.1
compatible applet targeting the Javacard Classic system, version 3.0.4. In a
nutshell, this lets you take a smartcard, install an app onto it,
and have it work as a FIDO2 authenticator device with a variety of
features. You can generate and use OpenSSH `ecdsa-sk` type keys, including
ones you carry with you on the key (`-O resident`). You can securely unlock
a LUKS encrypted disk with `systemd-cryptenroll`. You can log in to a Linux
system locally with [pam-u2f](https://github.com/Yubico/pam-u2f).

100% of the FIDO2 CTAP2.1 spec is covered, with the exception of features
that aren't physically on an ordinary smartcard, such as biometrics or
other on-board user verification. The implementation is not 100.0% standards
compliant, but you can expect very good results generally.

In order to run this outside a simulator, you will need
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

To set up and run these tests, use:

```shell
export JC_HOME=<your jckit> 
./gradlew jar testJar
python -m venv venv
./venv/bin/pip install -U -r requirements.txt
./venv/bin/python -m unittest discover -s python_tests
```

By default, these will use extremely fast interprocess communication with the JVM -
no PC/SC, just direct method calls on the running applet. The tests take less than
fifteen seconds to run, for me, even though there are almost two hundred cases.
You can change a variety of settings in `python_tests/ctap/ctap_test.py`,
such as enabling logging of all CTAP traffic, or making the JVM wait for a remote
debugger on startup, or using a VSmartCard PC/SC connection instead of direct method
invocation.

## Contributing

If you want to, feel free! Just raise a pull request or open an issue.

## Where to go Next

If you just want to install the app, look at [what you can configure](docs/installation.md).

I suggest [reading the FAQ](docs/FAQ.md) and perhaps [the security model](docs/security_model.md).

If you're a really detail-oriented person, you might enjoy reading
[about the implementation](docs/implementation.md).

## Implementation Status

| Feature                            | Status                                                  |
|------------------------------------|---------------------------------------------------------|
| CTAP1/U2F                          | Implemented (see [install guide](docs/certs.md))        |
| CTAP2.0 core                       | Implemented                                             |
| CTAP2.1 core                       | Implemented                                             |
| Resident keys                      | Implemented                                             |
| User Presence                      | User always considered present: not standards compliant |
| ECDSA (SecP256r1)                  | Implemented                                             |
| Other crypto, like ed25519         | Not implemented - availability depends on hardware      |
| Self attestation                   | Implemented                                             |
| Basic attestation with ECDSA certs | Implemented (see [install guide](docs/certs.md))        |
| Webauthn (NOT CTAP!) uvm extension | Implemented                                             |
| CTAP2.1 hmac-secret extension      | Implemented                                             |
| CTAP2.1 alwaysUv option            | Implemented                                             |
| CTAP2.1 credProtect option         | Implemented                                             |
| CTAP2.1 PIN Protocol 1             | Implemented                                             |
| CTAP2.1 PIN Protocol 2             | Implemented                                             |
| CTAP2.1 credential management      | Implemented                                             |
| CTAP2.1 enterprise attestation     | Implemented but never provided to RPs (defaulted off)   |
| CTAP2.1 authenticator config       | Implemented                                             |
| CTAP2.1 minPinLength extension     | Implemented, default max two RPIDs can receive          |
| CTAP2.1 credBlob extension         | Implemented, discoverable creds only                    |
| CTAP2.1 largeBlobKey extension     | Implemented                                             |
| CTAP2.1 authenticatorLargeBlobs    | Implemented, default 1024 bytes storage (max 4k)        |
| CTAP2.1 bio-stuff                  | Not implemented (doesn't make sense in this context?)   |
| APDU chaining                      | Supported                                               |
| Extended APDUs                     | Supported                                               |
| Performance                        | Adequate (sub-3-second common operations)               |
| Resource consumption               | Reasonably optimized for avoiding flash wear            |
| Bugs                               | Yes                                                     |
| Code quality                       | No                                                      |
| Security                           | Theoretical, but see "bugs" row above                   |

## Software Compatibility

| Platform              | Status           |
|-----------------------|------------------|
| Android (hwsecurity)  | Working          |
| Android (Google Play) | Broken [1]       |
| iOS                   | Reported working |
| Linux (libfido2)      | Working          |
| Windows 10            | Working          |

| Smartcard                                                                         | Status           |
|-----------------------------------------------------------------------------------|------------------|
| J3H145 (NXP JCOP3)                                                                | Working          |
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
   hardwired to use only "passkeys". If a site explicitly requests a non-discoverable credential,
   you will be prompted to use an NFC security key, but this is only CTAP1 and not CTAP2. There's
   nothing fundamentally preventing this from working on Android but the current state of Chrome
   and Fennec are that CTAP2 doesn't, because both use the broken Play Services library. It's also
   worth noting that if you install an untrusted attestation certificate, some implementations will
   reject your created U2F/CTAP1 credentials.
1. Some browsers support FIDO2 in theory but only allow USB security keys - this implementation
   is for PC/SC, and doesn't implement USB HID, so it will only work with FIDO2
   implementations that can handle e.g. NFC tokens instead of being restricted to USB.
   In order to use a smartcard in these situations you'll need https://github.com/StarGate01/CTAP-bridge
   or https://github.com/BryanJacobs/fido2-hid-bridge/ or similar, bridging USB-HID traffic to
   PC/SC.
