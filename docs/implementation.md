## Implementation Details

This page describes some of the key architectural choices of the applet.

### Coding Style

There are very few function calls in this application. Most code is explicit. This is due, in part, to
performance concerns, and in part due to the relatively highly optimized memory management. There's just
not much point to using a function if you couldn't safely _call_ it from any other context, or if it
took twenty input parameters and had five side effects...

### CBOR

Without dynamic memory allocation, parsing CBOR is difficult: it describes nested structures with varying
lengths.

This application doesn't parse CBOR so much as it streams it. Each byte is read in sequence, and occasionally
indexes into the stream are saved.

The key functions for doing this are `consumeAnyObject` (reads past the next CBOR entry), `consumeMapAndGetID`
(reads a map object and, after call, puts the index and length of its `id` entry into temp variables), and
`getMapEntryCount` (returns the number of entries in a map).

This strategy of linearly reading only works due to the CTAP requirement of canonical CBOR: there literally
is only one way to represent each input, and the fields must be in a defined order.

### Buffer Manager

Use of dynamic memory isn't really allowed on a Javacard. Nonetheless, we need access to dynamic-ish
structures to do things like computing hashes or signing data.

The BufferManager class abstracts away the use of dynamic memory. It can place allocations into four
different areas:

- The lower half of the APDU, "behind" the read cursor
- The upper half of the APDU, "above" where the output will reside (or in a place the output will be, 
  if the allocation is first freed)
- An in-memory temporary buffer
- A flash buffer as a last resort

In order to abstract away the choice of storage, allocating memory consists of three calls. The first
returns a "handle". The second uses the handle to get the byte buffer in which the storage is placed.
The third returns the offset into that byte buffer of the allocation.

In other words, when using the buffer manager, you must always use offsets - who knows what other data
are in the same buffer with your allocation?

Internally, the Buffer Manager uses three bytes of the in-memory buffer to record fill levels for
flash and RAM, and four bytes of the APDU - located around the 8k mark for very huge APDUs or at
the end for more reasonable ones - to track how much of the APDU is full.

This means individual allocations cannot be freed in arbitrary order: *all allocations must be released
in the opposite order in which they were allocated*, and also *the same size must be passed to the
free call as the allocate one*. The Buffer Manager doesn't track how many allocations have been made
only what size they are!

Handle IDs encode the buffer in which they're allocated:

- Large negative numbers are in memory
- Small negative numbers are in the APDU
- Positive numbers are in flash

Lower APDU space only becomes available when the `informAPDUBufferAvailability` call is made. Where an
allocation is allowed to live can be controlled by passing a parameter to the `allocate` call - don't
put something in the APDU if you want it to survive across another request!

### Status Bits

The `TransientStorage` class manages runtime state - state that mostly gets cleared when another applet
is selected. Sending "chained" APDU responses or receiving "chained" APDU requests is done by using the
`outgoingContinuation` and `chainIncomingRead` methods in that class. Incoming reads store a two-byte
offset, and outgoing continuations store both a two-byte offset and a two-byte total length.

All the data to be streamed (except possibly the first payload) should be in `bufferMem` before
setting up the streaming.

`TransientStorage` also contains bitfields for things like whether the authenticator has been "unlocked"
by a PIN since power-on, and if so what PIN protocol was used for it.

### Delivering Attestation Certificates

DER-encoded X.509 certificates can be, for this type of application, extremely large - multiple kilobytes.
In order to handle large certificates, a special bit in `TransientStorage` indicates that one of these is
necessary after the response. If that bit is set, the outgoing stream will continue from `attestationData`
after `bufferMem` is exhausted.

Unfortunately, the `largeBlobKey` extension places its own data AFTER the extremely long certificate. To
deal with this, a hack is used: the `largeBlobKey` is placed at the very end of `bufferMem` (in its last
32 bytes), and another bit in `TransientStorage` is set to indicate that when `attestationData` is empty,
those 32 bytes should be sent to the user.

### Credentials, IVs, and Wrapping Keys

Each credential this application produces is a combination of the SHA256 hash of an RPID and the
credential's own private key. It also contains a bit indicating whether the credential is discoverable,
a 16 byte IV for encryption, and a 16 byte HMAC for verification.

The discoverability bit is necessary because deleting a discoverable credential should invalidate it,
even if it is given back to the authenticator in an allowList.

Each RK gets a separate IV for each of its data structures:

- Encrypted user ID
- Encrypted RP name
- Public key (yes, this is stored encrypted)
- credBlob (don't confuse this with largeBlobKey)
- largeBlobKey (don't confuse this with credBlob)

When a particular item has a dynamic length, the length is stored unencrypted. All objects are multiples of 32
bytes long to allow easy AES256 decryption.

### Enumeration

Finding whether a particular credential is an RK is done by walking the list, and for each RK that is flagged
as valid (ie not deleted), doing a byte-exact comparison with the credential ID being checked.

Each RK has a bit that says whether it is a "representative" of a unique RP. This is set at the time the
credential is being stored. When a credential with this bit set is deleted, all the credentials are scanned
to find another credential sharing that same RP. If there is one, it is flagged as the new representative.

Enumerating assertions is done by storing, in memory, the relevant portions of the getAssertion request and
the index of the last resident key returned. The monotonic counter value at the time of creation is stored
in flash with each RK. `getNextAssertion` goes through the whole resident key list again and ignores any
that have counter values equal to or greater than the one at that index; this ensures that creds are produced
in the standard-specified "descending" order, but does mean that each `getNextAssertion` call takes time on
the order of the number of stored RKs.
