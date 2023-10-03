Authenticator Definition and Derived Authenticator Requirements
===============================================================

1.1
---
This authenticator meets the definition of Category 4: the entire Authenticator is implemented inside an AROE,
the Javacard Platform, executing inside a TEE. The TEE has GlobalPlatform TEE Protection Profile Certification,
and thus is a FIDO Allowed AROE. It additionally meets the definition of a Secure Element, and would
meet the definition of a FIDO Allowed AROE as such.

Name of the Authenticator: FIDO2Applet
Hardware Type & Version: NXP SmartMX3 P71
Underlying Software Platform/OS: NXP JCOP4 (Supported: Javacard 3.0.4+)

The authenticator logical boundary includes the implementation software (FIDO2Applet), the AROE (Javacard Platform),
and the TEE executing both.

The authenticator hardware boundary includes the P71 on which the AROE executes; the P71 unit includes transient memory,
processors, and persistent storage in one high integrated tamper-resistant package. The P71 provides a variety of
mitigations against hardware attacks, and the JCOP platform mitigates software attacks.

See especially [the security policy of the P71 module](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3746.pdf).


Transaction confirmation display is NOT implemented.

1.2
---
The authenticator uses AES-256, in the Cipher Block Chaining (CBC) mode of operation, for confidentiality of data.
Credential IDs are transmitted externally; these use an interally-stored SHA-256 for integrity.

All hashing uses SHA-256.

Data authentication uses HMAC in conjunction with SHA-256.

Random number generation is a hardware DRBG implemented by the TEE. The module performs power-on self tests checking
the integrity of the random number generation algorithm. It uses CTR_DRBG as specified by NIST SP800-90A and
provides 256 effective security bits.

For key derivation, the authenticator uses a feedback mode with HMAC (approved by NIST SP800-108) and SHA256 as the PRF.

All signatures are made using ECDSA on the NIST P-256 curve.

The authenticator does NOT provide anonymous attestation.

1.3
---
The user private key is stored inside the key handle. The key handle consists of:

AES256-CBC(BYTEMIX(Uauth.priv, SHA256(AppID)))

Where:

- AppID is the CTAP1 Application ID or the CTAP2 Relying Party ID
- Uauth.priv is the generated User Private Key, encoded as a raw point on the NIST P-256 curve
- BYTEMIX is a function interleaving its inputs, taking one byte at a time from each in sequence and so producing an
  output where, so long as the number of inputs is less than 16, every 16-byte block contains at least one byte from
  each input. This prevents the AES256-CBC output from having any single block entirely determined by input originating
  from outside the authenticator boundary

The Key Handle is used as the opaque Credential ID, for both discoverable and non-discoverable credentials.

1.4
---
The authenticator is a first-factor authenticator. It uses the Client PIN method to verify users.

1.5
---
The authenticator is a first-factor authenticator, NOT a second-factor authenticator.

1.6
---
The authenticator does NOT support Transaction Confirmation Display.

1.7
---
The authenticator does NOT use a KHAccessToken; the Key Handle is required to access a key. RP ID binding is
accomplished through the Key Handle containing the SHA256 hash of the Relying Party ID / App ID. The
authenticator software validates the RP ID through a separately computed hash of the requested RP prior to allowing
use of the key.

1.8
---
The authenticator does NOT use a KHAccessToken.

1.9
---
The authenticator does NOT support Transaction Confirmation Display.

1.10
----
The authenticator software implements a variety of input type and length checks on inputs. In addition to those,
the execution platform provides array bounds checking, pointer access checking, stack overflow mitigations, and
a wide variety of additional defenses against attacks relying on invalid inputs.

The AROE provides each hosted application an independent, separately protected memory space; the authenticator
software does not expose any functionality to other applications running inside the same AROE.

The authenticator does not store any data to, or retrieve any data from, unsecured storage. All used storage is
secured within the AROE boundary.

1.11
----
The authenticator does NOT have a Transaction Confirmation Display.

Key Management and Authenticator Security Parameters
====================================================

2.1.1
-----
The Authenticator Security Parameters are as follows:

| Parameter                        | Implementation       | Strength | Purpose                                                               | Secret | Sharing           | Storage            | Input         | Output          | Deleted                                     |
|----------------------------------|----------------------|----------|-----------------------------------------------------------------------|--------|-------------------|--------------------|---------------|-----------------|---------------------------------------------|
| User PIN derivative              | LEFT16(SHA-256(PIN)) | 128      | Determine if a pinUvAuthToken should be granted                       | N      | N/A               | None               | CTAP          | Never           | N/A                                         |
| PIN derivation salt              | 28-byte random value | 224      | Derive HMAC key from user PIN                                         | N      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  |
| PIN Verification Nonce           | 32-byte random value | N/A      | Verify the correct PIN was provided by the user using HMAC            | N      | Per authenticator | Flash              | Never         | Never           | CTAP pin set/change                         | 
| CTAP PIN Protocol 2 IVs          | 16-byte values       | N/A      | Prevent replay/modification of commands protected by PIN protocol 2   | N      | Per command       | None               | CTAP          | CTAP            | N/A                                         | 
| Credential Wrapping Key          | 32-byte random value | 256      | Encrypt/decrypt KeyHandles                                            | Y      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  | 
| Non-Discoverable Cred IV         | 16-byte random value | N/A      | Make first block of KeyHandles less predictable                       | N      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  | 
| Non-Discoverable CredProt-3 IV   | 16-byte random value | N/A      | Distinguish non-discoverable credProtect=3 credentials                | N      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  | 
| CTAP Platform Agreement Key      | EC key on P-256      | 128      | ECDH-generate a shared secret between Authenticator and Platform      | Y      | Per authenticator | RAM                | Never         | Public via CTAP | Applet deselect OR as per CTAP standard     | 
| CTAP Platform shared secret      | 32-byte negotiated   | 256      | Communicate securely with a connected FIDO platform                   | Y      | Per authenticator | RAM                | Half via CTAP | Never           | Applet deselect OR as per CTAP standard     | 
| CTAP pinToken                    | 32-byte random value | N/A      | Allow or deny CTAP operations that require a PIN                      | N      | Per authenticator | RAM                | CTAP          | CTAP            | Applet deselect OR as per CTAP standard     | 
| CTAP permissions byte            | 1-byte stored value  | N/A      | Check permissions of pinToken                                         | N      | Per authenticator | RAM                | Never         | Never           | Applet deselect OR as per CTAP standard     | 
| PIN retry counter                | 1-byte stored value  | N/A      | Count number of times a PIN may be used before locking                | N      | Per authenticator | Flash              | Never         | CTAP            | CTAP reset OR correct PIN entry             | 
| PIN retry power-off bit          | 1-bit stored value   | N/A      | Require a power-off before a PIN may be used again                    | N      | Per authenticator | RAM                | Never         | CTAP            | Applet reset                                | 
| PIN change required bit          | 1-bit stored value   | N/A      | Require a PIN change before a CTAP PIN/UV token will be issued        | N      | Per authenticator | Flash              | CTAP          | CTAP            | CTAP pin set/change or CTAP reset           | 
| PIN minimum length               | 1-byte stored value  | N/A      | Minimum allowable PIN length in UTF-8 codepoints                      | N      | Per authenticator | Flash              | CTAP          | CTAP            | CTAP setMinPinLength or CTAP reset          | 
| CTAP signature counter           | 4-byte stored value  | N/A      | Ensures every signature is different; wear-leveled across 64 bytes    | N      | Per authenticator | Flash              | Never         | CTAP            | CTAP reset                                  | 
| NFC lock state                   | 1-bit stored value   | N/A      | Prevents authenticator from being used after NFC power-off requested  | N      | Per authenticator | RAM                | NFC           | Never           | Applet reset                                | 
| Attestation Private Key          | ECDSA key on P-256   | 128      | Generate attestation signatures                                       | Y      | Shared            | Flash              | Vendor[1]     | Never           | Never                                       | 
| Non-Discoverable Credential Key  | ECDSA key on P-256   | 128      | Generate credential signatures                                        | Y      | Per credential    | RAM/External       | CTAP in Cred  | CTAP in Cred    | From RAM immediately after use              | 
| CTAP HMAC extension UV bytes     | 32-byte random value | 256      | Derive CTAP2.1 HMAC Extension key from cred with UV                   | N      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  | 
| CTAP HMAC extension non-UV bytes | 32-byte random value | 256      | Derive CTAP2.1 HMAC Extension key from cred without UV                | N      | Per authenticator | Flash              | Never         | Never           | CTAP reset                                  |
| Discoverable Cred IV             | 16-byte random value | N/A      | Ensure every credential has different stored encrypted blocks         | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     | 
| Discoverable Credential Key      | ECDSA key on P-256   | 128      | Same as non-discoverable credential private keys                      | Y      | Per credential    | Flash/RAM/External | Never[2]      | CTAP in Cred    | When credential deleted; from RAM after use | 
| Discoverable RP IV               | 16-byte random value | N/A      | Ensure every stored relying party ID has different encrypted blocks   | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     | 
| Discoverable Relying Party ID    | AES256(RP ID)        | N/A      | Stored SHA-256 hash of relying party ID                               | N      | Per credential    | Flash              | CTAP          | CTAP            | When credential deleted                     | 
| Discoverable User IV             | 16-byte random value | N/A      | Ensure every username has different stored encrypted blocks           | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     | 
| Discoverable Username            | AES256(Username)     | N/A      | Stored user name for credential                                       | N      | Per credential    | Flash              | CTAP          | CTAP            | When credential deleted                     | 
| Discoverable Public Key IV       | 16-byte random value | N/A      | Ensure every public key has different stored encrypted blocks         | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     | 
| Discoverable Public Key          | AES256(PubKey)       | N/A      | Stored public key for credential as uncompressed X, Y points on P-256 | N      | Per credential    | Flash              | Never         | CTAP            | When credential deleted                     | 
| Discoverable CredBlob IV         | 16-byte random value | N/A      | Ensure every CredBlob has different stored encrypted blocks           | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     | 
| Discoverable CredBlob            | AES256(CredBlob)     | N/A      | Stored CredBlob for CTAP2.1 CredBlob extension                        | N      | Per credential    | Flash              | CTAP          | CTAP            | When credential deleted                     | 
| Discoverable LargeBlob IV        | 16-byte random value | N/A      | Ensure every LargeBlobKey is unique to a credential                   | N      | Per credential    | Flash              | Never         | Never           | When credential deleted                     |

[1] The attestation private key is installed by the vendor during the authenticator setup process, prior
to first use

[2] Although discoverable credential keys are provided to the authenticator inside Credential IDs via CTAP, the
stored key (which is checked to be identical) is the source used for cryptographic operations

Only the attestation private key is shared between authenticators. All other ASPs are specific to an
individual device.

Note: Every value deleted on "applet deselect" is also deleted when power is removed from the authenticator,
or when the applet is uninstalled, or when a CTAP reset operation is performed.

Note: In every case where AES-256-CBC is used, an Initialization Vector (IV) is also used. Every IV is
unique except for that used for wrapping non-discoverable Credential IDs, which is shared across
credentials.

Note: User-private data are stored encrypted inside the authenticator implementation, even though the authenticator
software executes inside an AROE. These data are encrypted using unique IVs so as to prevent an inspection of the
flash contents disclosing e.g. shared usernames or RP IDs between two different stored credentials.

2.1.2
-----
All ASPs are stored inside the AROE, and protected by its mechanisms. See details in the table above,
for question 2.1.1.

2.1.3
-----
Please see the effective security bit strength of keys in table 2.1.1, above.

2.1.4
-----
The overall claimed strength of the authenticator is 128 bits. The "weakest link" is the generated
ECDSA credentials on the P-256 curve, which have a strength of 128 security bits. The user's PIN
as provided in CTAP is also a 128 bit value. All wrapping/storage operations are at least 224 security bits
in strength, not degrading the underlying 128-bit keys.

2.1.5
-----
All ASPs stored inside the AROE are protected against modification and substitution by the secure
element on which the authenticator software executes.

Credential IDs for non-discoverable credentials are stored externally. They are protected against
modification as documented in section 1.3; due to the mixture of credential and Relying Party ID
the difficulty of modifying the credential in a way that still allows its use is greater than
128 effective security bits.

2.1.6
-----
All ASPs stored inside the AROE are protected against disclosure by the secure element on which
the authenticator code executes.

2.1.7
-----
The only ASPs that are stored externally and not also stored internally are non-discoverable
KeyHandles (inside a credential ID). They are made confidential using AES-256, an approved algorithm.
They are protected against unauthorized replay - after a CTAP authenticator reset - through the
regeneration of the "Credential Wrapping Key" and "Non-Discoverable Cred IV" ASPs. Regenerating
these ASPs prevents any previously-valid credentials from being valid, with a strength of 128 or
more security bits.

Other ASPs are stored internally and the internal copy is checked to prevent invalid data from
being accepted, whether in the context of a replay attack or otherwise.

2.1.8
-----
External KeyHandles are protected using AES-256 with CBC, an approved algorithm.

2.1.9
-----
External KeyHandles are protected using AES-256 with CBC, an effective strength of 256 bits. The
KeyHandles themselves are ECDSA keys on NIST P-256, which has an effective strength of 128 bits.
Therefore the claimed strength of the wrapping key is greater than the claimed strength of the
one being wrapped.

The portion of the user's PIN delivered by the CTAP protocol has 128 security bits. To verify this,
an HMAC operation in feedback mode (an approved KDF) is performed on the incoming PIN derivative. The
ASPs for the derivation provide 224 security bits, greater than the 128 for the incoming PIN part.

These are the only cases where keys are wrapped by the authenticator implementation.

2.1.10
------
Each external KeyHandle contains two parts: the private keying material, and the SHA-256 hash
of the relying party ID for which the key is valid. Prior to allowing the use of the KeyHandle,
it is decrypted using AES-256-CBC, and the relying party ID is validated.

Because the decryption is performed using a key and IV that are specific to the authenticator, 
a KeyHandle from another authenticator would - excepting a coincidence unlikely to happen even
1 in 2^128 times, a cryptographic collision - not validate.

Additionally, discoverable credentials are stored on the authenticator itself, and only
incoming Credential IDs that exactly match them are used.

2.1.11
------
The authenticator does NOT use the KHAccessToken method.

2.1.12
------
As discussed in 1.3, the AppID / Relying Party ID is validated prior to use by comparing its
SHA-256 hash with the stored value.

Additionally, discoverable credentials are stored on the authenticator itself, and only
incoming Credential IDs that exactly match them are used.

2.1.13
------
The CTAP2 makeCredential and CTAP1 Register commands result in a unique credential for
each invocation. The credential private keys are randomly generated by the AROE, using
hardware-backed key generation capabilities.

2.1.14
------
The authenticator supports Full Basic Attestation, and only generates (and thus signs)
valid attestation objects.

The authenticator does NOT support ECDAA Attestation.

2.1.15
------
The authenticator only produces well-formed signature assertions, and does not use user
Uauth.priv keys for any other cryptographic purpose.

2.1.16
------
When an ASP is stored in RAM, it is cleared automatically by the execution environment when
the applet is deselected or power is removed to the authenticator. When an ASP is stored in
flash, it is destroyed by performing a transactional overwrite of the value. Either the
destroy operation returns an error (and the value is still valid), or the value is
overwritten and the operation returns a success.

An authenticator reset notably overwrites the "wrapping" ASPs; as these are required to use
credentials, the credentials are effectively destroyed by destroying the only means of
decrypting them.

2.1.17
------
The authenticator can be factory-reset by uninstalling the applet code from the Javacard environment.

When this happens, all stored authenticator data are deleted, including the fixed attestation certificate.

2.1.18
------
All ASPs that are to be used as keys are generated in accordance with the FIPS 140-2 standard.

2.1.19
------
The authenticator does NOT store or output biometric data.

The authenticator does NOT store or output user verification reference data.

2.1.20
------
As discussed in 1.3, UAuth.priv is stored inside an AES256-CBC encryption. The encryption uses
two ASPs specific to this authenticator (and which are also deleted by a CTAP reset operation).

As only one authenticator has a given credential wrapping key ASP, only it can unwrap UAuth.priv.

Random Number Generation
========================
2.2.1
-----
All key generation uses the random number generation algorithm described in 1.2.

Key derivation by HMAC (an Allowed Key Derivation Function) with SHA-256 is used to generate
keys for the Large Blob Storage and HMAC-Secret extensions.

Key derivation by HMAC (an Allowed Key Derivation Function) is used to verify the user's PIN.

2.2.2
-----
The security strength of the AROE's random number generator is at least 256 bits, the largest
claimed strength of any key generated or used.

The security level of the only used Key Derivation Function (HMAC with SHA-256) is 256 bits.
This matches the claimed strength of the largest derived key.

2.2.3
-----
All nonces are produced with the random number generation algorithm described in 1.2, which
is an Allowed Random Number Generator.

2.2.4
-----
The authenticator is a FIDO2 implementation.

2.2.5
-----
The SmartMX3 chip on which the authenticator software executes uses an Allowed Physical
True Random Number Generator to seed its RNG. Random number generators other than the
ones provided by the AROE (and thus backed by the hardware implementation) are NOT used.


Signature and Registration
==========================
2.3.1
-----
The authenticator implements a global signature counter, shared by all keys.
Privacy-impact-mitigation measures other than advancing the counter by a random amount
on each operation are NOT implemented.

2.3.2
-----
The authenticator increases its global signature counter by a random value between one and
sixteen, inclusive, on each operation.

The signature counter is global and starts at (or resets to) zero. However, as it is incremented
prior to being returned for any operation, all signature counter values emitted are greater than zero.

Authenticator's Test for User Presence and User Verification
============================================================
3.1
---
The authenticator assumes user presence in inserting the authenticator into a contacted smartcard reader
or bringing it near a near-field reader.

3.2
---
The authenticator supports FIDO2 client PINs as a verification method. As client PINs may or may not be provided, the
authenticator metadata lists both client-pin and USER_VERIFY_NONE.

3.3
---
Question 3.3 was removed from the standard.

3.4
---
The authenticator does not support caching user verification.

Each PIN/UV token may be used for a single operation, and is marked invalid immediately upon verification.

3.5 - 3.6
---------
Questions 3.5 and 3.6 were removed from the standard.

3.7
---
The authenticator implements the external user verification method "clientPin". This method is indicated both in the
FIDO metadata for the authenticator and via the Webauthn UVM extension.

The channel between the authenticator and the user is protected by the FIDO protocol standard methods. The protection
of the authenticator itself is strong enough to resist moderate or high effort software and hardware attacks.

3.8
---
The authenticator only implements clientPin user verification. The FIDO protocol inherently provides protections
against replay (via the platform-authenticator shared secret) and injection (via a signature over the incoming request)
attacks.

The only means of providing user verification to the authenticator are via CTAP operations.

Additionally, the user's PIN is not stored inside the authenticator directly. Instead, a key derived from it is used
to check a stored nonce.

3.9
---
The authenticator implements FIDO default PIN rate limiting. Three attempts are allowed, after which the authenticator
must be powered off, such as by removing from the smartcard reader or NFC antenna. Deselecting the applet does not
allow further PIN attempts without power being cut.

After the first power-off, the authenticator again allows three PIN attempts, after which it must again be powered off.

After the second power-off, the authenticator allows a final two PIN attempts. After these, it is permanently locked
and can only be used again after a CTAP reset operation.

The authenticator implemenets no verification methods beyond user PINs. There is no rate limiting of attempts to
brute-force the PIN/UV token, but the issued token is a 32 byte random value: a brute force attack on the PIN/UV token
is more difficult than a brute force attack on the user credential.

3.10
----
The authenticator does not support biometric methods.

3.11
----
The authenticator always returns support for the clientPin option in the GetInfo response, the only verification method
it supports. No additional methods may be added.

The authenticator does not support a means of changing the PIN outside the CTAP protocol.

Privacy
=======
4.1
---
The authenticator uses an attestation key shared across all devices.

4.2
---
The authenticator does not provide "enterprise attestations", or any other authenticator-unique information to any
Relying Party. The AAGUID and attestation public keys are shared across all implementations of the authenticator.

Other information that may be provided to a Relying Party on user request, such as the minimum PIN length, does not
uniquely identify a single authenticator.

4.3
---
KeyIDs / Credential IDs produced by the authenticator are opaque to the relying party. As AES256-encrypted values,
they appear random from the outside.

As there is no externally-visible information of any kind in the Credential ID, it cannot be correlated with the
authenticator or another Credential ID.

As the AAGUID is shared across all devices for this authenticator, knowing the AAGUID only indicates the authenticator
model and not one individual device.

4.4
---
The authenticator returns CTAP_OK in response to delete operations containing invalid or previously deleted credentials.

In the case of discoverable credentials, this is largely irrelevant for privacy, as deleting a credential requires
PIN verification, and possessing the user's PIN allows the use of the CTAP Credential Managmeent APIs that disclose the
stored credentials. But it prevents the disclosure of the validity of a non-discoverable credential.

4.5
---
The authenticator has two methods that reveal whether a Credential ID is registered. The first is the CTAP GetAssertion
operation, and the second is the CTAP Credential Management operations.

The GetAssertion operation requires user verification - via a client PIN - to permit an empty AllowList. If the
AllowList is NOT empty, stored credentials are NOT used. This means that GetAssertion requires either a Credential ID
or user verification to generate a signature.

The Credential Management API always requires user verification.

So, all methods that reveal a credential require either user verification or a provided Credential ID.

4.6
---
The authenticator implements the CredProtect extension.

4.7
---
For discoverable credentials, the credProtect level is stored alongside the credential itself inside the authenticator.
When an attempt is made to use the credential (whether via an AllowList or otherwise), this level is consulted and used
to ensure the CTAP credProtect extension requirements are met.

For non-discoverable credentials, at creation time one of two different Initialization Vectors is used in wrapping the
KeyHandle into the Credential ID. The first IV is for credentials with no credprotect level, and for those with 
credProtect levels one or two. The second IV is for credentials with credProtect level three.

At the time a credential is used, no attempt to decrypt it with the credProtect-three-only IV is made unless user
verification has been performed.

As the use of a different IV completely changes the resulting encrypted Credential ID, this means that
credProtect-level-three non-discoverable credentials will appear just like completely invalid credentials.

credProtect level one and two non-discoverable credentials are not stored on the authenticator itself, so the only
way they can be considered for use is if they are presented in an AllowList to the GetAssertion call. This satisfies
the requirements for credProtect levels one and two, and no further checking is required.

The CTAP1 Authenticate operation does NOT attempt to use the IV for non-discoverable level three credentials, and does
NOT allow the use of discoverable credentials with a stored credProtect level of three.

In all cases, a credential whose use is not allowed by security requirements is ignored; at no point is it revealed
that the credential would have been valid with a higher level of user verification.

No checking of the credProtect level is performed by the Credential Management APIs, as they require user verification
and thus satisfy the requirements for credProtect level three.

4.8
---
The authenticator is a FIDO device. It reveals stored usernames via the FIDO Credential Management APIs, which require
user verification.

4.9
---
The authenticator is a FIDO device. It does not output unencrypted app IDs or key handles except through the FIDO
Credential Management APIs, which require user verification.

4.10
----
As per answers 4.2 and 4.3, the authenticator does not implement Enterprise Attestation, and does not allow the
correlation of Credential IDs or other generated material across devices and relying parties.

4.11
----
The authenticator contains some code for Enterprise Attestation, but it is disabled and cannot be activated.

4.12
----
The enterprise attestation feature is disabled.

Physical Security, Side Channel Attack Resistance and Fault injection Resistance
================================================================================
5.1
---
The physical and side channel attack prevention methods are documented by NXP, the vendor for the TEE on which
the authenticator software executes.

5.1.1
-----
The TEE on which the authenticator is based provides extensive protection against side channel attacks.

The authenticator code does not further mitigate these.

5.2
---
Question 5.2 was removed from the standard.

5.3
---
The authenticator is resistant to physical tampering thanks to its highly integrated TEE package.

5.4
---
The authenticator implements a four-byte CTAP signature counter. The signature counter is incremented by a random
value between one and sixteen on each use. When the signature counter hits its maximum value, no further credentials
may be created or used.

This imposes an effective maximum use limit on all ASPs other than the attestation key of 2^32 operations.

The attestation key is not directly use-limited; instead, it is time-limited (which also implicitly creates a use limit,
due to the inherent limit on the rate at which operations may be performed by an authenticator).

5.5
---
The TEE on which the authenticator code executes provides mitigations against side channel power-usage and radio
leakage attacks.

5.6
---
The TEE on which the authenticator code executes provides mitigations against side channel and timing attacks. At no
point does the authenticator code behave differently based on the value contained within a key ASP; all core
cryptographic operations are performed in hardware by the TEE.

Thus, the effective security of all ASPs maintain their full strength values even in the presence of timing observation.

5.7
---
All cryptographic operations are performed in hardware, and the number of iterations/calls to the hardware/backed
function does NOT depend on the value of any ASP.

5.8
---
The physical module on which the authenticator code executes does not contain any physical or logical debug interfaces.

The authenticator software does not expose additional logical debug interfaces.

5.8.1
-----
The physical module on which the authenticator code executes does not provide debug functionality.

5.9
---
The TEE on which the authenticator code executes is resistant to fault injection attacks.

Attestation
===========
6.1
---
The authenticator uses a single attestation certificate shared across all devices, but this is because all devices
are the same authenticator model. No other model uses the same attestation certificate.

6.2
---
There is no variation in the security characteristics within the devices sharing the AAGUID. All devices are
identically configured.

6.3
---
The FIDO metadata statement accurately describes the authenticator.

6.4
---
The attestation root certificate is unique to this authenticator. The attestation certificate contains the
relevant AAGUID extension, with its value set to the authenticator's AAGUID.

6.5
---
The attestation certificate contains the authenticator AAGUID.

6.6
---
The authenticator does NOT have Enterprise Attestation support.

Operating Environment
=====================
7.1
---
The authenticator application runs in an AROE, as described in the answer to question 1.1.

7.2
---
The authenticator software makes use of the cryptographic functionality provided by the AROE; the AROE is configured to
provide it. No functionality used by the application is disabled.

7.3
---
The Javacard environment provided by the JCOP 4 OS protects each applet's memory space against access from another
applet.

It is possible to allocate "shared" or "exported" objects that disable this protection; additionally, static variables
are also not subject to the same security controls. For this reason, the authenticator applet does NOT provide any
exported interfaces, and does NOT store any FIDO-relevant data in static variables.

7.4
---
The operating environment is deployed in a configuration that does NOT permit any modification that would compromise
the security of the authenticator. Additional applets may be installed, but their execution and storage is logically
isolated from that of the authenticator by the AROE.

7.5
---
The security configuration of the AROE is under the control of the vendor and/or its delegates. The only change that
can be made after shipment is to remove the applet, or install it (again) if not present. The install process is also
fully under the control of the authenticator vendor and/or its delegates.

7.6
---
The security characteristics of the authenticator are not modifiable by anyone after installation, including the
authenticator device vendor. The security characteristics at install time may only be modified by the authenticator
vendor and/or its delegates.

7.7
---
The authenticator does NOT have Enterprise Attestation support.

Self-Tests and Firmware Updates
===============================

8.1
---
The authenticator IS resistant to induced fault analysis, due to the implementation of its TEE.

8.1.1
-----
The authenticator IS resistant to induced fault analysis.

8.2
---
The authenticator does NOT mediate (and does NOT permit) the update of its software, save by complete removal and
reinstallation. This installation process is fully under the control of the authenticator vendor and/or its delegates,
and the application to be loaded is verified using an Allowed Data Authentication method.

8.3
---
The authenticator IS resistant to induced fault analysis.

8.4
---
The authenticator IS resistant to induced fault analysis.

Manufacturing and Development
=============================
9.1
---
No ASPs are generated during manufacturing; they are generated at the point the authenticator software is loaded into
the TEE.

9.2
---
TODO - attestation private key access policy

9.3
---
TODO - facilities security

9.4
---
The authenticator source code, supporting documentation, and tool chain exact versions are revision controlled through
the use of a git repository.

9.5
---
The git revision control system assigns a unique identifier to every version.

9.6
---
TODO - physical plant security around attestation keys

Operational Guidance
====================
10.1
----
The authenticator does not support Enterprise Attestation.
