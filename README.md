# FIDO2 CTAP2 Javacard Applet

## Overview

This repository contains sources for a FIDO2 CTAP2 compatible(-ish)
applet targeting the Javacard Classic system, version 3.0.4. In a
nutshell, this lets you take a smartcard, install an app onto it,
and have it work as a FIDO2 authenticator device with a variety of
features. You can generate and use OpenSSH `ecdsa-sk` type keys. You
can securely unlock a LUKS encrypted disk with `systemd-cryptenroll`.

This applet does **not** presently implement U2F support, for
[valid reasons](docs/FAQ.md).

In order to run this, you will need
[a compatible smartcard](docs/requirements.md).

You might be interested in [reading about the security model](docs/security.md).

## Building the application

You'll need to get a copy of:
- com.licel.jcardsim-3.0.5
- JavacardKit, version 3.0.4 (`jckit_304`)

Drop the jcardsim jar into the root of the repository. Set the
environment variable `JC_HOME` to point to your jckit folder.

Run `./gradlew buildJavaCard`, which will produce a `.cap` file
for installation.

## Testing the application

While you can test on an actual smartcard, I prefer to use VSmartCard
and run JCardSim connected to that. There are a few example JCardSim
unit tests in the repository, but you'll get much better analysis
of the behaviour by using real applications or other testing suites
like SoloKey's `fido2-tests`, which you can run against the simulated
application.

The `VSim` class might get you started.

## Contributing

If you want to, feel free!

## Where to go Next

I suggest [reading the FAQ](docs/FAQ.md) and perhaps [the security model](docs/security.md).

## Implementation Status

| Feature                        | Status                                                  |
|--------------------------------|---------------------------------------------------------|
| CTAP1/U2F                      | Not implemented                                         |
| CTAP2.0 core                   | Implemented, many caveats                               |
| Resident keys                  | Implemented, default 50 slots                           |
| User Presence                  | User always considered present: not standards compliant |
| Self attestation               | Implemented                                             |
| Attestation certificates       | Not implemented                                         |
| ECDSA (SecP256r1)              | Implemented                                             |
| Other crypto like ed25519      | Not implemented                                         |
| CTAP2.0 hmac-secret extension  | Implemented                                             |
| CTAP2.1 alwaysUv extension     | Implemented                                             |
| CTAP2.1 credProtect extension  | Implemented, one caveat                                 |
| CTAP2.1 PIN Protocol 1         | Implemented                                             |
| CTAP2.1 PIN Protocol 2         | Not implemented                                         |
| CTAP2.1 credential management  | Implemented                                             |
| CTAP2.1 Enterprise attestation | Not implemented                                         |
| CTAP2.1 authenticator config   | Not implemented                                         |
| CTAP2.1 blob storage           | Not implemented                                         |
| APDU chaining                  | Supported                                               |
| Extended APDUs                 | Supported                                               |
| Performance                    | Adequate                                                |
| Resource consumption           | Constant, but unoptimized                               |
| Bugs                           | Yes                                                     |
| Code quality                   | No                                                      |
