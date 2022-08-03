# Frequently Asked Questions

## How can you have an FAQ on a newly-created repository? Surely the questions aren't frequent yet.

You caught me, I'm a fraud and these are anticipatory questions.

## What's FIDO2?

If you don't know what that is, you don't need this.

## What's a JavaCard?

If you don't know what that is, you DEFINITELY don't need this.

## Don't you need a CBOR parser to write a CTAP2 authenticator?

Apparently not. Instead of implementing a real CBOR parser I just
poured more sweat into the implemnentation, and added a topping of
non-standards-compliance.

As a result of not having a proper CBOR parser, the app will often
return undesirable error codes on invalid input, but it should
handle most valid input acceptably.

## Why did you write this, when someone else said they were almost done writing a better version?

Well, they said that, but they hadn't published the source code and I got impatient.

Two is better than zero, right?

## Why did you write this at all?

I was pretty unhappy with the idea of trusting my "two factor" SSH
keys' security to a closed-source hardware device, and even the
existing open hardware devices didn't work the way I wanted.

I wanted my password to be used in such a way that without it, the
authenticator was useless - in other words, a true second factor.

So I wrote a CTAP2 implementation that [had that property](security.md).

## You say there are "caveats" for some implementation bits. What are those?

Well, first off, this app doesn't attempt to do a full CBOR parse, so its error
statuses often aren't perfect and it's generally tolerant of invalid input.

Secondly, OpenSSH has a bug that rejects makeCredential responses
that don't have credProtect level two when it requests level two. The
CTAP2.1 standard says it's okay to return level three if two was requested,
but that breaks OpenSSH, so... credProtect is incorrectly implemented in
that it always applies level three internally.

## Why don't you implement U2F/CTAP1?

U2F doesn't support PINs, and requires an attestation certificate.

[the security model](security.md) requires PINs.
