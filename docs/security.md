# Security Model

First off, this application is likely not secure. It hasn't been
audit, fuzz tested, or even really tested at all. That means
there's very likely a critical bug that breaks its model.

This page aims to describe the **theoretical** security of the
app, with that in mind. It focuses on cases where this authenticator
deviates from what you might expect from the CTAP2 standard.

## Principle: PINs Matter

The core principle of a FIDO2 device is to be one of two factors.
The authenticator represents "something you have". The PIN represents
"something you know".

Gaining complete access to the authenticator should not be useful for
an attacker unless they know your PIN.

Traditional implementations of FIDO2 devices do this by storing the
PIN on the device "securely", and then relying on the correctness
of their software and the tamper-proofness of their hardware to
protect private keying material.

This app is different. In this app, once you set a PIN, the "wrapping
key" - without which the authenticator is useless - is encrypted using
a key derived from the PIN. This means no credentials can be created
or used unless you provide your PIN...

## Details: Security Levels

On boot, the device generates an AES256 key, the "wrapping key".

Each individual credential issued by the app is a SecP256r1 keypoint,
generated randomly on-device for that credential. The private key
is then AES256-CBC encrypted along with the RP ID, using a random
IV, and the result is used as the "credential ID".

This means relying parties are holding their own encrypted private
keys. The keypair itself provides approximately 128 bits of
brute-force resistance. The wrapping key provides a strong 256 bits.

The wrapping key is - when a PIN is set - encrypted using a "PIN key"
produced by running five (by default) rounds of PBKDF2 over the first
sixteen bytes of a SHA-256 of the user's PIN, with a 28-byte random
salt. This means that "unwrapping" the wrapping key, were an attacker
to gain access to it, would require a targeted attack whose brute-force
difficulty is at most 128 bits, and is likely set by the entropy of
the user's PIN.

**Use a strong PIN** if you care about security in the event your
device is entirely compromised. Despite the name, there is no
requirement that PINs be numeric. You can use any sequence of
characters up to 64 bytes long.

### hmac-secret keys

The hmac-secret extension keys are made by performing an HMAC-SHA256
of a particular credential's ECDSA private key, using a unique
32-byte key. This makes the brute-force resistance of these keys
dependent on the entropy in a raw ECDSA private key, which is
somewhat less than 256 bits and likely considerably stronger
than the ECDSA keypair itself.

## Threat Modeling

### An attacker has my device and knows my PIN

The attacker is you. Do better next time.

### An attacker can intercept traffic to and from my authenticator

Yeah, that's how NFC works.

The important parts of the traffic are encrypted and authenticated
with ECDH. The attacker cannot reasonably "see" your PIN. They can
see incidental data like credential IDs being newly created, but
the security impact is minimal.

If they can forge traffic to the authenticator, they could hard-reset it,
wiping your keys.

### An attacker has malware on the machine I'm using with my authenticator

- The attacker could reset the authenticator, deleting your keys
- They could keylog your PIN, removing its additional security, but
  only when you provide it on the compromised machine
- They could attempt to guess your PIN, but they only get eight tries
- If they DO get your PIN, they can use the authenticator as you
  for the duration it's connected to the compromised machine
- If you haven't set a PIN, that's the same as them knowing your PIN
  for this threat model

### An attacker has physical acccess to my smartcard, and I didn't set a PIN

The attacker has fully compromised your security and can use the
authenticator to pretend to be you in any way it is able.

Resident keys stored on the device will let the attacker see your
user IDs on different web sites, etc. They can use those to log
in to those sites.

Non-resident keys are slightly better: the attacker has to guess
which service you'd registered with, and your username.

### An attacker has physical access to my smartcard, but I set a PIN

If the smartcard itself is physically secure, this is the same as
the "malware" case above. **If not**, then we are in an interesting
situation.

The attacker needs to decrypt the on-device wrapping key. Without
doing that, they can see incidentals like:
- how many different resident keys you've stored on the device
- how long each key's RP ID is, if less than 32 characters
- how long each key's user ID is
- how many different RPs in total have resident keys on the device

What they can't do without decrypting the wrapping key is get at
your actual credentials for sites - the private keys, the RP IDs,
etc. They might - if your device doesn't support transient memory
for EC private keys AND was inopportunely powered off the last time
you used it - be able to use the most recently used keypair you did.

#### Decrypting the wrapping key

As described above, the wrapping key is itself encrypted using
PBKDF2 with a very low iteration count, performed on the first
sixteen bytes of your PIN's SHA256 hash. This means the attacker is
unlikely to already HAVE a rainbow table, but they can start
brute-forcing your PIN.

If you used a strong PIN, you're likely okay for quite a while.

### I left my authenticator plugged into my computer, after entering my PIN

Anyone can use your authenticator as you. Despite what the CTAP2 standard
says about user presence, it's not readily possible to implement
a "timeout" on a Javacard 3.0.4 device. Javacard 3.1 introduces an
(unreliable) uptime counter....

But the implementation currently always assumes user presence.

This Could Be Better.
