# Installation Parameters

This applet provides a variety of install-time configurable settings. These are configured via a
CBOR map provided when the applet is installed (for example, via `gp --install <applet> --params <params>`).

To generate the parameter string, use the `get_install_parameters.py` script at the root of the repository.
The help the script provides (`--help`) explains each options.

The defaults - when no install parameters are provided - are for maximum FIDO standards compatibility, but
won't accept an attestation certificate. So if you want CTAP1/U2F, you'll need to install the applet with
parameters.

If you want attestation to work, you'll also need to run `./install_attestation_cert.py` after installing the
applet itself!

## Android installation

For the Android installation to work with the native system UI provided by the Google Play Services, the
applet needs to be the default selected applet on the card.

You can do that with `gp --install <applet> --params <params> --privs CardReset`

The reason is that Google Play Services send the `SELECT` APDU using extended-length encoding while the
GlobalPlatform manager of JavaCards does not support that.
By having the applet be the default selected applet, it can bypass GlobalPlatform and handle the `SELECT`
by itself.
