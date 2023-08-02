# Security Model

First off, this application is likely not secure. It hasn't been
audit, fuzz tested, pentested, whatever. That means
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

This app is different. In this app, when you set a PIN, the authenticator
enables the `alwaysUv` option - requiring the PIN for all credential
creation and use. The "wrapping key" - without which the authenticator
cannot accesss its resident/discoverable credentials - is encrypted
using a key derived from the PIN. In other words, if you could read all
the authenticator's memory when a PIN is set, you would only find
encrypted data.

Any "level 3" protected credential also uses that high-security key,
even when non-discoverable.

## Details: Security Levels

On boot, the device generates two AES256 keys: the "high security
wrapping key" and the "low security wrapping key".

Each individual credential issued by the app is a SecP256r1 keypoint,
generated randomly on-device for that credential. The cred private key
is then AES256-CBC encrypted along with the RP ID, using a random
IV, and the result is used as the "credential ID". Which wrapping key
is used depends on how the credential is generated:

- credentials stored on the authenticator itself ("discoverable") use
  the high security key
- credentials created with `credProtect` level 3, "require user
  verification for any discovery" also use the high security key
- other credentials (non-discoverable, `credProtect` level zero
  through two) use the low security key

When using resident keys, the cred private key is only stored encrypted
(after being initially generated). When not using resident keys, the
cred private key isn't stored on the authenticator at all.

This means relying parties are holding their own encrypted private
keys. The keypair itself provides approximately 128 bits of
brute-force resistance. The wrapping keys provide a strong ~255 bits.

The high security wrapping key is - when a PIN is set - encrypted using
a "PIN key" produced by running five (by default) rounds of PBKDF2 over
the first sixteen bytes of a SHA-256 of the user's PIN, with a 28-byte
random salt. This means that "unwrapping" the wrapping key, were an
attacker to gain access to it, would require a targeted attack whose
brute-force difficulty is at most 128 bits, and is likely set by the
entropy of the user's PIN.

The low security wrapping key is stored on the authenticator in the clear.

**Use a strong PIN** if you care about security in the event your device
is entirely compromised. Despite the name, there is no requirement that
PINs be numeric. You can use any sequence of characters up to 63 bytes long.

To use the resident keys or high-security non-resident ones, your PIN is
used for challenge-response to the authenticator at least once
per power-up, and it's done encrypted over an ECDH channel. The
authenticator returns a  32-byte "pinToken", also encrypted. From then on
proof of possession of the PIN is via challenge-response using 16 bytes of
the hash of whatever content with pinToken as the key.

In other words, it's pretty secure. The PIN token is rerandomized each time a
guess is unsuccessful and each authenticator reset. You can't intercept
someone's PIN except when it's being initially set, and even then it's sent
encrypted with ECDH. The least secure part of it is when the **initial** PIN
is being set - so do that first!

The high security wrapping key is stored in RAM from when you enter your PIN
until you reset the card, so if you want to be very secure, power the card
down each time you finish using it.

### hmac-secret keys

The hmac-secret extension keys are made by performing an HMAC-SHA256
of a particular credential's ECDSA private key, using a random 32-byte
key generated when the app is first installed (one for UV, a different one for
non-UV). This makes the brute-force resistance of these keys dependent on the
entropy in a raw ECDSA private key, which is somewhat less than 256 bits and
likely considerably stronger than the ECDSA keypair itself.

## Threat Modeling

### An attacker has my device and knows my PIN

The attacker is you. Do better next time.

### An attacker can view traffic to and from my authenticator

Yeah, that's how NFC works when your attacker has a nice antenna.

The important parts of the traffic are encrypted and authenticated
with ECDH. The attacker cannot reasonably "see" your PIN. They can
see incidental data like credential IDs being newly created, but
the security impact is minimal.

If they can forge traffic to the authenticator, they could hard-reset it,
wiping your keys.

### An attacker can man-in-the-middle traffic to and from my authenticator

This threat scenario is explored in depth elsewhere, but in brief:

- The CTAP2.1 `credManagement` functions are protected using the PIN as a private
  key, so a MITM cannot just delete your credentials
- The authenticator reset function is anonymous and could be performed by a MITM
- Setting a PIN for the first time is not secure over a compromised channel
- Creating new credentials and getting assertions over a channel with an active
  MITM will reveal the first sixteen bytes of the SHA256 of your PIN, which is
  all that FIDO2 uses. You'll need to change your PIN after this happens

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

If the smartcard itself is physically secure against having its
flash memory read or computation corrupted, this is the same as
the "malware" case above. **If not**, then we are in an interesting
situation.

If you set the alwaysUv flag, the attacker needs to decrypt the
on-device wrapping key. Without doing that, they can read incidentals like:
- how many different resident keys are currently stored on the device
- how long each key's RP ID is, if less than 32 characters
- how long each key's user ID is
- how many different RPs in total have resident keys on the device
- the credProtect level of each resident key

What they can't do without decrypting the wrapping key is get at
your actual credentials for sites - the private keys, the RP IDs,
etc. They might - if your device doesn't support transient memory
for EC private keys AND was inopportunely powered off the last time
you used it - be able to use the most recently used keypair you did.

However, if they were to also get a hold of a non-discoverable credential for
a site that uses credProtect levels zero, one, or two, they could impersonate
you to that site.

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

This Could Be Better. In the meanwhile, perhaps use an NFC device and
physically remove it when not in use.

### I gave my smartcard to somebody but I didn't "lock" the card

They could probably install an applet that would make the scenario
identical to one where they possessed the card AND the hardware
was faulty.

So, lock your smartcard ("set a transit key"), `gpp --lock <key>` or 
however you communicate with it.

### I deleted a resident key and then someone compromised my card

Deleting a credential doesn't currently wipe it from the flash, just
marks it as trashed. But a compromised card is a compromised card...

### My smartcard's random number generator is not really random

Keys generated by the card will be weak, so the "wrapping key" will be weak.

This entirely breaks the security model of the card and you can't trust
anything it does.

### I don't trust your code

You can see the code, and modify it until you do trust it. The only homespun
crypto in the repository is an implementation of HMAC and an implementation
of PBKDF2. Those were written because PBKDF2 isn't part of the Javacard API
at all, and although HMA-SHA256 is it's not implemented on any of my cards.

Open source is open.
