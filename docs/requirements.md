# Runtime requirements

This app requires Javacard 3.0.4. I really, really, really wanted to
support Javacard 3.0.1, which runs on cool products like the
Mclear/NFCRings.com OMNI Ring (seriously nice tech!).

Unfortunately, CTAP2.0 requires an EC diffie-helmann key exchange
in order to support PINs or the hmac-secret extension, and it uses
DH with a SHA256 hash. Javacard 3.0.1 officially supports only ECDH-SHA1.
Javacard 3.0.4 doesn't support ECDH-SHA256 either... but it provides
a "plain" variant that returns the raw DH output which you then
hash yourself - good enough for me.

So it's not possible to make this app work in a meaningful way on
the original Javacard 3.0.1 or earlier **as the spec is written** (see below!).

You might think you could implement ECDH yourself in software. I don't think
you're right. ECDH agreement is just one, simple, elliptic-curve multiplication
operation. But these processors don't even have 32-bit integers, much less the
128-bit ones we'd be using. It would just be too slow to be reasonable. It's
not feasible, sorry.

HOWEVER, there do exist cards that support the appropriate algorithms atop Javacard
3.0.1. Those will work. In fact, the OMNI Ring itself is one of those! Check
[JCAlgTest](https://github.com/crocs-muni/JCAlgTest) on your target card. You need:

- KeyBuilder `LENGTH_AES_256` (symmetric crypto for credential ID wrapping BUT also used
  for communication between the card and the platform)
- Cipher `ALG_AES_BLOCK_128_CBC_NOPAD` (using symmetric crypto - note this is AES with
  256-bit keys and 128-bit blocks, aka AES256, despite the 128 in the alg name)
- Cipher getInstance `CIPHER_AES_CBC PAD_NOPAD` (using symmetric crypto)
- KeyPair on-card generation `ALG_EC_FP LENGTH_EC_FP_256` (core ECDSA keypair generation)
- KeyBuilder `TYPE_EC_FP_PRIVATE LENGTH_EC_FP_256` (core ECDSA keypair usage)
- Signature `ALG_ECDSA_SHA_256` (actually signing card-produced results)
- KeyAgreement `ALG_EC_SVDP_DH_PLAIN` (used in combo with SHA256 to implement secure channel
  between the card and the platform)
- MessageDigest `ALG_SHA_256` (used to implement HMAC-SHA256 for verifying PINs, etc, and
  for the above-mentioned secure channel)
- RandomData `ALG_SECURE_RANDOM` (used for key generation etc. Note `ALG_KEYGENERATION` is not
  used, that's too new)
- Almost 2k total memory including a small amount of `MEMORY_TYPE_TRANSIENT_RESET` and a 
  larger amount of `MEMORY_TYPE_TRANSIENT_DESELECT` (there is an optional boolean to minimize
  memory usage in the code - this cuts RAM usage down to around 128 bytes at the cost of flash wear)
- About 200 bytes max commit capacity, used for atomically creating and updating resident
  keys
- An amount of `MEMORY_TYPE_PERSISTENT` sufficient to hold the app and the resident keys, etc

Signature `ALG_HMAC_SHA_256` is missing from the above list, because the HMAC part
is implemented in software (using the OS-provided SHA256).

You also **want** the following to avoid having flash storage wear each time the card is
powered up, and the risk of private keys being stored there in the first place:

- `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (ideal) or `TYPE_EC_FP_PRIVATE_TRANSIENT_RESET`
- `TYPE_AES_TRANSIENT_DESELECT` (ideal) or `TYPE_AES_TRANSIENT_RESET`

So to summarize, let's discuss the full requirements on the authenticator side:

- Javacard Classic 3.0.4 caveatted as above
- Approximately 2kB of total RAM OR ~128 bytes plus comparatively more flash wear
- A 256 byte APDU buffer (most cards have this although the standard only mandates 128 bytes)
- Support for AES256-CBC
- Support for ECDH-plain
- Support for SHA-256 hashing
- Support for EC with 256-bit keys
- Approximately 20k of storage by default (very tunable)
- Ideally, support for EC TRANSIENT_DESELECT keys, as otherwise you'll get flash usage 
  every time the app is selected

An example of a card I've tested working is the NXP J3H145, but many
others should work fine too.

# Platform-side requirements

On the computer side of things, you'll likely want `libfido2` compiled
with support for PC/SC, which is currently experimental, and/or `libnfc`. On
Arch Linux this is not the default - out of the box `libfido2` only works with
USB HID tokens, which this is **not**. I have uploaded [an AUR package with
the appropriate support for your convenience](https://aur.archlinux.org/packages/libfido2-full).

Without either of those two options you will Have A Bad Day.

If you have them, you should see the card start showing up in the output
of `fido2-token -L`. You can see what gets sent to and from the card by
setting `FIDO_DEBUG=1` before running your command.
