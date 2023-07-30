# Frequently Asked Questions

## How can you have an FAQ on a newly-created repository? Surely the questions aren't frequent yet.

You caught me, I'm a fraud and these are anticipatory questions.

## What's FIDO2?

If you don't know what that is, you don't need this.

## What's a Javacard?

If you don't know what that is, you DEFINITELY don't need this.

## Don't you need a CBOR parser to write a CTAP2 authenticator?

Apparently not. Instead of implementing a real CBOR parser I just
poured more sweat into the implementation, and added a topping of
non-standards-compliance.

As a result of not having a proper CBOR parser, the app will often
return undesirable error codes on invalid input, but it should
handle most valid input acceptably.

It does this by linearly scanning a byte-buffer with the CBOR object in it,
and moving a read index forward the desired amount. Unknown objects get skipped.
Any object declaring a length greater than two bytes long causes an error,
because it's not possible to have >65535 of something in a 1,024-byte-long
buffer, and the CTAP2 standard requires that CBOR be "canonical".

## Why did you write this, when someone else said they were almost done writing a better version?

Well, they said that, but they hadn't published the source code and I got impatient.

Two is better than zero, right?

UPDATE: this repository was published in 2022, and as of 2023 (more than a year
later) there are zero other open-source CTAP2 Javacard implementations available,
so far as I can tell. There's a difference between talking about doing something
and actually doing it.

## Why did you write this at all?

I was pretty unhappy with the idea of trusting my "two factor" SSH
keys' security to a closed-source hardware device, and even the
existing open hardware devices didn't work the way I wanted.

I wanted my password to be used in such a way that without it, the
authenticator was useless - in other words, a true second factor.

So I wrote a CTAP2 implementation that [had that property](security_model.md).

## You say there are "caveats" for some implementation bits. What are those?

Well, first off, this app doesn't attempt to do a full CBOR parse, so its error
statuses often aren't perfect and it's generally tolerant of invalid input.

Secondly, OpenSSH has a bug that rejects makeCredential responses
that don't have credProtect level two when it requests level two. The
CTAP2.1 standard says it's okay to return level three if two was requested,
but that breaks OpenSSH, so... credProtect is incorrectly implemented in
that it always applies level three internally.

Thirdly, the CTAP API requires user presence detection, but there's really no
way to do that on Javacard 3.0.4. We can't even use the "presence timeout"
that is described in the spec for NFC devices. So you're always treated as
being present, which is to some extent offset by the fact that anything real
requires you type your PIN (if one is set)... Additionally, this app will not
clear CTAP2.1 PIN token permissions on use.

So set a PIN, and unplug your card when you're not using it.

Fourthly, implementing credProtect by storing a different value for every
credential is a royal pain: it would require the key's generated credential IDs
to be longer than the minimum 64 bytes. Rather than do that, this implementation
just rejects the creation of high-credProtect credentials while a PIN is unset.

So, again, set a PIN.

Finally, the CTAP2.0 and CTAP2.1 standards are actually mutually incompatible. When
a getAssertion call is made with an `allowList` given, CTAP2.0 says that the
authenticator should iterate through assertions generated with the matching
credentials from the allowlist. CTAP2.1 says the authenticator should pick one
matching credential, return an assertion generated with it, and ignore any
other matches. 

This implementation uses the CTAP2.1 behavior. Because one or the other must be
chosen, it can't be both fully CTAP2.0 compatible and CTAP2.1 compatible at the same time.

Another more minor difference is that CTAP2.0 allows PINs of 64 bytes or longer.
This authenticator and CTAP2.1 cap PINs at 63 bytes long.

## Why don't you implement U2F/CTAP1?

U2F doesn't support PINs.

[The security model](security_model.md) requires PINs.

It would be possible to implement U2F commands in non-standards-compliant ways,
but implementing them the normal way would require turning off the `alwaysUv`
key feature for U2F-accessible credentials.

## Isn't PBKDF2 on a smartcard a fig leaf?

Probably, yes, but it makes me feel better.

You can raise the iteration count, but really there's only so much that can be
done here. At least it means off-the-shelf rainbow tables probably won't work.

## I hear bcrypt or Argon2id is better than PBKDF2

Good luck implementing those on a 16-bit microprocessor. I welcome you to try.

## What does this implementation store for resident keys?

It will store:
- the credential ID (an AES256 encrypted blob of the RP ID SHA-256
  hash and the credential private key)
- up to 32 characters of the RP ID, again AES256 encrypted
- a max 64-byte-long user ID, again AES256 encrypted
- the 64-byte public key associated with the credential, again AES256 encrypted
- A 16-byte random IV used for encrypting the RP ID, user ID, and public key
- the length of the RP ID, unencrypted
- the length of the user ID, unencrypted
- a boolean set to true on the first credential from a given RP ID, used
  to save state when enumerating and counting on-device RPs
- a four-byte counter value tracking which credential was most recently created
- how many distinct RPs have valid keys on the device, unencrypted
- how many total RPs are on the device, unencrypted

This is the minimum to make the credentials management API work. It would
be possible to encrypt the length fields too, they just aren't and I didn't
see it as important.

The default is to have fifty slots for resident keys, which is double what a
Yubikey supports. You can turn this up, with a performance and flash cost, or
turn it down with a performance and flash benefit.

## Why is the code quality so low?

You're welcome to contribute to improving it. I wrote this for a purpose and
it seems to work for that purpose.

Please remember that this code is written for processors that don't have an
`int` type - only `short`. Most function calls are a runtime overhead, and
each object allocation comes out of your at-most-2kB of RAM available. You
can't practically use dynamic memory allocation at all, it's just there to tease
you.

The code I wrote may look ugly, and it's certainly not perfect, but it is
reasonably efficient in execution on in-order processors with very limited
stacks.

A perfect example of this is the BufferManager class. It looks like a mess, but
it makes it possible to use both sides of the APDU buffer as transient memory,
avoiding flash wear on very memory-constrained devices.

## I'm getting some strange CBOR error when I try to use this

Run the app in JCardSim with VSmartCard and hook up your Java debugger.
See what's going on. Raise a pull request to fix it.

## Can you make this work on Javacard 2.2.1?

Ahahahahahahahaahha

Javacard versions before 3.0.1 don't support SHA-2 hashing. Not gonna happen.

## What does this applet mean for the flash storage lifetime of my smartcard?

On every makeCred or getAssertion operation, the app will:

- Increment a flash-stored counter (1-4 bytes written)
- Set an elliptic curve private key object

The applet will try to allocate the EC private key object in RAM, but will fall back to flash if
the smartcard doesn't support RAM-backed allocations or doesn't have enough RAM. The flash-stored
counter is wear-leveled across 67 bytes.

On every powerup or unsuccessful PIN attempt, the app will set an elliptic curve private key object.

On every PIN attempt, the app will overwrite a PIN retry counter... whether the PIN attempt is
successful or not. But that's one byte written for a failure, or two bytes for a success. The PIN
retry counter is wear-leveled across 64 bytes.

Additionally, creating or deleting resident keys will (of course) write to flash, and there are some
initial flash writes when installing or resetting the applet.

Overall, this applet is pretty great at keeping everything in RAM, and you're much more likely
to be given trouble by software bugs than by your flash write endurance. Flash is never used as
writable buffer space if your smartcard has at least 2k of RAM, is only used for long request
chaining if your smartcard has 1k of RAM, and is only used for "ordinary" requests if you're under
around 200 bytes of RAM. Great care has been taken to make sure the most common operations like
getPinToken and getKeyAgreement don't write to flash.

If you want to assess exactly what is and is not in RAM on your particular Javacard, you can install
the applet and send APDUs like the following:

    gpp -d -a 00A4040008A0000006472F000100 -a 801000000145FF

(This is an app select, followed by the CTAP2 vendor use area command `0x45`)

The result that comes back can be decoded by passing it to the included `decode_bufinfo.py` script.

## Can I update the app and maintain the validity of my previously-issued credentials?

No. Once you start using a certain version of the applet, you're stuck on that version if you
want the issued credentials to stay valid. Have multiple authenticators, eh?

## Are there any limits to how long I can keep using this on a card?

Each time you create a credential or get an assertion (regardless of whether the credential is
discoverable or not) a counter is incremented. When it hits its maximum value of 2^32 you must
reset the authenticator (invalidating all created credentials) to continue using the app. This counter is
shared across all credentials, discoverable or otherwise.

2^32 is 4,294,967,296 - large enough that you could use the token once per second for 136 years
without reaching the maximum value.

That should be enough longevity.

The only other limit to be aware of is the PIN retry count - if you incorrectly attempt a PIN eight
times (by default) across three power-ups of the authenticator without successfully entering it once,
the app will be locked and you won't be able to use it without clearing everything.

## I'm getting "operation denied" for certain requests

The authenticator will refuse to create credProtect=2 discoverable credentials, or any
credProtect=3 credentials, without a PIN set. This is to avoid needing to store the
credProtect status of the credential alongside it.

If you want to use this authenticator with those relying parties, set a PIN.
