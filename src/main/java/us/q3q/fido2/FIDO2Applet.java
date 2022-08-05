package us.q3q.fido2;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

import javacardx.crypto.Cipher;

public class FIDO2Applet extends Applet implements ExtendedLength {

    // Configurable parameters
    /**
     * If true, permit the creation of resident keys without a PIN being set or provided.
     * This is "normal" for a FIDO2 authenticator, but means keys on the device could be
     * accessed in the event of a software bug or hardware fault.
     */
    private static final boolean ALLOW_RESIDENT_KEY_CREATION_WITHOUT_PIN = false;
    /**
     * Size of buffer used for receiving incoming data and sending responses.
     * To be standards-compliant, must be at least 1024 bytes, but can be larger.
     */
    private static final short BUFFER_MEM_SIZE = 1024;
    /**
     * Amount of "scratch" working memory
     */
    private static final short SCRATCH_SIZE = 280;
    /**
     * Number of resident key slots - how many credentials can this authenticator store?
     */
    private static final short NUM_RESIDENT_KEY_SLOTS = 50;
    /**
     * How long an RP's user identifier is allowed to be - affects storage used by resident keys
     */
    private static final short MAX_USER_ID_LENGTH = 64;
    /**
     * How long an RP identifier is allowed to be for a resident key. Values longer than this are truncated
     */
    private static final short MAX_RESIDENT_RP_ID_LENGTH = 32;
    /**
     * Number of iterations of PBKDF2 to run on user PINs to get a crypto key.
     * Higher means it's slower to get a PIN token, but also harder to brute force the device open with physical
     * access to it. Can theoretically be any number but surely there are limits to how long you're willing to
     * wait, and there's no way a smartcard is outcompeting a desktop computer...
     */
    private static final short PIN_KDF_ITERATIONS = 5;
    /**
     * Number of times PIN entry can be attempted before the device will self-lock. FIDO2 standard says eight.
     */
    private static final short MAX_PIN_RETRIES = 8;
    /**
     * How many times a PIN can be incorrectly entered before the authentiator must be rebooted to proceed.
     * FIDO2 standard says three.
     */
    private static final short PIN_TRIES_PER_RESET = 3;

    // Fields for decoding incoming APDUs and encoding outgoing ones
    /**
     * Total byte length of output FIDO2 Credential ID struct
     */
    private static final short CREDENTIAL_ID_LEN = 64;
    /**
     * Length of scratch space used for decrypting credentials
     */
    private static final short PRIVATE_SCRATCH_SIZE = CREDENTIAL_ID_LEN;
    /**
     * Byte length of one EC point
     */
    private static final short KEY_POINT_LENGTH = 32;
    /**
     * Byte length of hashed relying party ID
     */
    private static final short RP_HASH_LEN = 32;
    /**
     * Byte length of hashed client data struct
     */
    private static final short CLIENT_DATA_HASH_LEN = 32;
    /**
     * Required byte length of wrapped incoming PINs
     */
    private static final short PIN_PAD_LENGTH = 64;
    /**
     * Request/response buffer
     */
    private final byte[] bufferMem;
    /**
     * General working memory
     */
    private final byte[] scratch;
    /**
     * Decrypted credential ID holder
     */
    private final byte[] privateScratch;
    /**
     * True if the device has been locked with a PIN; false in initial boot state before PIN set
     */
    private boolean pinSet;
    /**
     * AESKey.setKey doesn't take a byte array length param, so we use this temp space to store key bytes
     */
    private final byte[] privateKeySpace;
    /**
     * Random key for deriving keys for the hmac-secret extension from regular credential private keys
     */
    private final byte[] hmacWrapperBytes;

    /**
     * Set of short variables held in memory for generally avoiding flash use
     */
    private final short[] tempShorts;
    /**
     * Used for storing found indices in searches
     */
    private static final short IDX_TEMP_BUF_IDX_STORAGE = 0;
    /**
     * Used for storing found lengths in searches
     */
    private static final short IDX_TEMP_BUF_IDX_LEN = 1;
    /**
     * When writing an overlong response using chained APDUs, stores the position we're up to in the outgoing buffer
     */
    private static final short IDX_CONTINUATION_OUTGOING_WRITE_OFFSET = 2;
    /**
     * When writing an overlong response using chained APDUs, stores the remaining bytes in the outgoing buffer
     */
    private static final short IDX_CONTINUATION_OUTGOING_REMAINING = 3;
    /**
     * When reading an overlong incoming request using chained APDUs, stores the fill level of the incoming buffer
     */
    private static final short IDX_CHAINING_INCOMING_READ_OFFSET = 4;
    /**
     * When reading incoming request chains, which FIDO2 command the request represents (pulled from the first packet)
     */
    private static final short IDX_STORED_COMMAND_BYTE = 5;
    /**
     * How full the scratch buffer is
     */
    private static final short IDX_SCRATCH_ALLOC_SIZE = 6;
    /**
     * Number of times a PIN has been attempted since last reset
     */
    private static final short IDX_PIN_TRIES_SINCE_RESET = 7;
    /**
     * Index of next credential to consider when iterating through RPs with credManagement commands
     */
    private static final short IDX_RP_ITERATION_POINTER = 8;
    /**
     * Index of next credential to consider when iterating through creds with credManagement commands
     */
    private static final short IDX_CRED_ITERATION_POINTER = 9;
    /**
     * Total number of in-memory short variables
     */
    private static final short NUM_TEMP_SHORTS = 10;

    // Fields for negotiating auth with the platform
    /**
     * authenticator transient key
     */
    private final KeyPair authenticatorKeyAgreementKey;
    /**
     * key to be set based on platform<->authenticator shared secret
     */
    private final AESKey sharedSecretKey;
    /**
     * DH for platform <-> authenticator secure channel
     */
    private final KeyAgreement keyAgreement;
    /**
     * encipher things destined for the platform
     */
    private final Cipher sharedSecretWrapper;
    /**
     * decipher things sent by the platform
     */
    private final Cipher sharedSecretUnwrapper;
    /**
     * must be zeroes. Is used for encryption and decryption of messages between authenticator and platform
     */
    private static final byte[] ZERO_IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    /**
     * per-reset random proxy used instead of true user PIN, as proof PIN was obtained
     */
    private final byte[] pinToken;
    /**
     * Decrypter used to unwrap data by using a key derived from the user's PIN
     */
    private final Cipher pinUnwrapper;

    /**
     * array of per-reset booleans used internally
     */
    private final boolean[] tempBools;
    /**
     * set when authenticator key initialized
     */
    private static final short IDX_RESET_PLATFORM_KEY_SET = 0;
    /**
     * set when PIN has been provided (device unlocked)
     */
    private static final short IDX_RESET_PIN_PROVIDED = 1;
    /**
     * set if platform supports authenticator-compatible key
     */
    private static final short IDX_RESET_FOUND_KEY_MATCH = 2;
    /**
     * set if the "up" (User Presence) option is enabled
     */
    private static final short IDX_OPTION_UP = 3;
    /**
     * set if the "uv" (User Validation) option is enabled
     */
    private static final short IDX_OPTION_UV = 4;
    /**
     * set if the "rk" (Resident Key) option is enabled
     */
    private static final short IDX_OPTION_RK = 5;
    /**
     * number of booleans total in array
     */
    private static final short NUM_RESET_BOOLS = 6;

    /**
     * per-device salt for deriving keys from PINs
     */
    private final byte[] pinKDFSalt;
    /**
     * key to be set from KDF derivation of PIN
     */
    private final AESKey pinWrapKey;
    /**
     * used for signing the authData we send to the platform, to prove it came from us
     */
    private final Signature attester;

    // Fields for wrapping and unwrapping platform-held blobs
    /**
     * The most important crypto object in the whole application. Stored in non-volatile memory; resetting this
     * renders all issued credentials unusable. Generated on install, regenerated on CTAP-reset-command.
     *
     * If a PIN is set, these bytes are stored encrypted using a key derived from the PIN.
     */
    private final byte[] wrappingKeySpace;
    /**
     * Authenticator-specific master key, decrypted (if necessary) and loaded into transient storage for use
     */
    private final AESKey wrappingKey;
    /**
     * random IV for authenticator private wrapping
     */
    private static byte[] wrappingIV;
    /**
     * first half random data, second half the HMAC of that using the wrapping key:
     * used for checking if a potential wrapping key is the correct one
     */
    private final byte[] wrappingKeyValidation;
    /**
     * encrypt data using authenticator master key
     */
    private final Cipher symmetricWrapper;
    /**
     * decrypt data using authenticator master key
     */
    private final Cipher symmetricUnwrapper;
    /**
     * Randomness.
     */
    private final RandomData random;

    // Fields for maintaining auth state
    /**
     * Ever-increasing number representing how many sig operations we've made
     */
    private final byte[] counter;
    /**
     * Value that decreases with each failed PIN guess
     */
    private short pinRetryCounter = MAX_PIN_RETRIES;

    // Parameters for the real elliptic-curve keys :-)
    /**
     * The actual per-credential key pair
     */
    private final KeyPair ecKeyPair;
    /**
     * A private key for an incoming credential
     */
    private final ECPrivateKey ecPrivateKey;
    /**
     * General hashing of stuff
     */
    private final MessageDigest sha256;

    // Data storage for resident keys
    /**
     * Encrypted-as-usual credential ID fields for resident keys, just like we'd receive in incoming blocks
     * from the platform if they were non-resident
     */
    private final byte[] residentKeyData;
    /**
     * A boolean stating whether the resident key is valid (stored, usable) or not
     */
    private final boolean[] residentKeyValidity;
    /**
     * Encrypted (with the device wrapping key) user ID fields for resident keys
     */
    private final byte[] residentKeyUserIds;
    /**
     * Length of the corresponding user IDs
     */
    private final byte[] residentKeyUserIdLengths;
    /**
     * Encrypted (with the device wrapping key) RP ID fields for resident keys
     */
    private final byte[] residentKeyRPIds;
    /**
     * Length of the corresponding RP IDs
     */
    private final byte[] residentKeyRPIdLengths;
    /**
     * Encrypted (with the device wrapping key) public key X+Y point data for resident keys
     */
    private final byte[] residentKeyPublicKeys;
    /**
     * Set to true for each (valid) resident key that has a "unique" RP - used to speed up
     * enumerating RPs while preserving privacy. Note that this doesn't mean it's the only
     * RK with a particular RP; it is just set on exactly ONE RK for each distinct RP
     */
    private final boolean[] residentKeyUniqueRP;
    /**
     * How many resident key slots are filled
     */
    private byte numResidentCredentials;
    /**
     * How many distinct RPs are present across all resident keys
     */
    private byte numResidentRPs;

    // Parameters for canned responses
    private static final byte[] U2F_V2_RESPONSE = {
            0x55, 0x32, 0x46, 0x5F, 0x56, 0x32
          //   U     2     F     _     V     2
    };
    private static final byte[] FIDO_2_RESPONSE = {
            0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30
          //   F     I     D     O     _     2     _     0
    };
    private static final byte[] HMAC_SECRET_EXTENSION_ID = {
            0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // hmac-secret
    };
    private static final byte[] CRED_PROTECT_EXTENSION_ID = {
            0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, // credProtect
    };
    private static final byte[] AUTH_INFO_RESPONSE = {
            FIDOConstants.CTAP2_OK,
            (byte) 0xA5, // Map - five keys
                0x01, // map key: versions
                    (byte) 0x81, // array - one item
                        0x68, // string - eight bytes long
                        0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30, // FIDO_2_0
                0x02, // map key: extensions
                    (byte) 0x82, // array - two items
                        0x6B, // string - eleven bytes long
                            0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, // credProtect
                        0x6B, // string - eleven bytes long
                            0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // hmac-secret
                    0x03, // map key: aaguid
                        0x50, // byte string, 16 bytes long
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // aaguid
                0x04, // map key: options
                    (byte) 0xA4, // map: four entries
                        0x62, // string: two bytes long
                            0x72, 0x6B, // rk
                            (byte) 0xF5, // true
                        0x68, // string - eight bytes long
                            0x61, 0x6c, 0x77, 0x61, 0x79, 0x73, 0x55, 0x76, // alwaysUv
                            (byte) 0xF5, // true
                        0x68, // string - eight bytes long
                            0x63, 0x72, 0x65, 0x64, 0x4d, 0x67, 0x6d, 0x74, // credMgmt
                            (byte) 0xF5, // true
                        0x69, // string: nine bytes long
                            0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x69, 0x6e, // clientPin
    };
    private byte[] aaguid = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    private static final byte[] MAKE_CREDENTIAL_RESPONSE_PREAMBLE = {
            0x00, // status - OK!
            (byte) 0xA3, // Map - three keys
                0x01, // map key: fmt
                    0x66, // string - six bytes long
                    0x70, 0x61, 0x63, 0x6B, 0x65, 0x64, // packed
                0x02, // map key: authData
    };
    private static final byte[] PUBLIC_KEY_ALG_PREAMBLE = {
            (byte) 0xA5, // map - five entries
                0x01, // map key: kty
                    0x02, // integer (2) - means EC2, a two-point elliptic curve key
                0x03, // map key: alg
                    0x26, // integer (-7) - means ES256 algorithm
                0x20, // map key: crv
                    0x01, // integer (1) - means P256 curve
                0x21, // map key: x-point
                    0x58, // byte string with one-byte length next
                        0x20 // 32 bytes long
    };
    private static final byte[] PUBLIC_KEY_DH_ALG_PREAMBLE = {
                0x01, // map key: kty
                    0x02, // integer (2) - means EC2, a two-point elliptic curve key
                0x03, // map key: alg
                    0x38, 0x18, // integer (-25) - means ECDH with SHA256 hash algorithm
                0x20, // map key: crv
                    0x01, // integer (1) - means P256 curve
                0x21, // map key: x-point
                    0x58, // byte string with one-byte length next
                        0x20 // 32 bytes long
    };
    private static final byte[] ATTESTATION_STATEMENT_PREAMBLE = {
            0x03, // map key: attestation statement
            (byte) 0xA2, // map - two entries
                    0x63, // string - three bytes long
                        0x61, 0x6C, 0x67, // alg
                        0x26, // integer (-7) - means ES256 algorithm
            0x63, // string: three characters
                        0x73, 0x69, 0x67, // sig
                        0x58, // byte string with one-byte length
    };
    private static final byte[] SINGLE_ID_MAP_PREAMBLE = {
            (byte) 0xA1, // map: one entry
                0x62, // string - two bytes long
                    0x69, 0x64, // id
    };

    /**
     * Deliver a particular byte array to the platform
     *
     * @param apdu Request/response object
     * @param array Bytes to send
     * @param len Length to send, starting at byte zero
     */
    private static void sendByteArray(APDU apdu, byte[] array, short len) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(array, (short) 0, buffer, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Convenience method sending a whole byte array to the platform
     *
     * @param apdu Request/response object
     * @param array Byte array to send in its entirety
     */
    private static void sendByteArray(APDU apdu, byte[] array) {
        sendByteArray(apdu, array, (short) array.length);
    }

    /**
     * Sends a CTAP error (not an ISO7816 error!) to the platform.
     * Also resets any APDU chaining state.
     *
     * @param apdu Request/response object
     * @param sendByte Byte representing the CTAP error state
     */
    private void sendErrorByte(APDU apdu, byte sendByte) {
        tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
        tempShorts[IDX_CRED_ITERATION_POINTER] = 0;
        tempShorts[IDX_RP_ITERATION_POINTER] = 0;
        scratchRelease(); // Just in case

        byte[] buffer = apdu.getBuffer();
        buffer[0] = sendByte;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        throwException(ISO7816.SW_NO_ERROR);
    }

    /**
     * Allocates some in-memory scratch space. Consecutive calls always give contiguous memory.
     * After a successful call, the requested amount of space is reserved in scratch at the returned
     * offset. This memory should be freed with a corresponding call to scratchRelease in reverse order.
     *
     * @param numBytes Amount of scratch space, in bytes, to allocate
     *
     * @return Index of the allocation's start in the scratch buffer
     */
    private short scratchAlloc(short numBytes) {
        short ret = tempShorts[IDX_SCRATCH_ALLOC_SIZE];
        if (ret > (short)(SCRATCH_SIZE - numBytes)) {
            throwException(ISO7816.SW_FILE_FULL);
        }
        tempShorts[IDX_SCRATCH_ALLOC_SIZE] += numBytes;
        return ret;
    }

    /**
     * Releases ALL scratch space allocated through scratchAlloc
     */
    private void scratchRelease() {
        tempShorts[IDX_SCRATCH_ALLOC_SIZE] = 0;
    }

    /**
     * Releases the most recent allocation(s) of scratch space totaling exactly the given
     * number of bytes. Behavior undefined (silent corruption) if the most recent non-released
     * allocation(s) do NOT exactly total numBytes. There is no way to release earlier allocations
     * except through correctly ordered release calls.
     *
     * @param numBytes The number of bytes to release
     */
    private void scratchRelease(short numBytes) {
        tempShorts[IDX_SCRATCH_ALLOC_SIZE] -= numBytes;
    }

    /**
     * Increment the four-byte-long credential usage counter by one
     */
    private void incrementCounter() {
        JCSystem.beginTransaction();
        if (counter[3] == (byte) 0xFF) {
            if (counter[2] == (byte) 0xFF) {
                if (counter[1] == (byte) 0xFF) {
                    if (counter[0] == (byte) 0xFF) {
                        // Completely full. No more sigs.
                        throwException(ISO7816.SW_FILE_FULL);
                    }
                    counter[0] = (byte)(((short)counter[0]) + 1);
                    counter[1] = 0;
                }
                counter[1] = (byte)(((short)counter[1]) + 1);
                counter[2] = 0;
            }
            counter[2] = (byte)(((short)counter[2]) + 1);
            counter[3] = 0;
        }
        counter[3] = (byte)(((short)counter[3]) + 1);
        JCSystem.commitTransaction();
    }

    /**
     * Fully read an incoming request into bufferMem. In the event the request is larger
     * than the buffer, throws an exception. After call, request chaining variables will
     * be set appropriately if the request is part of a chained sequence.
     *
     * @param apdu Request/response object
     * @param buffer APDU data buffer (not bufferMem)
     * @param lc Length of request received from the platform
     * @param amtRead Amount of the request already read into the APDU buffer
     */
    private void fullyReadReq(APDU apdu, byte[] buffer, short lc, short amtRead) {
        short chainOff = tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET];
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(),
                bufferMem, chainOff, amtRead);

        short curRead = amtRead;
        while (curRead < lc) {
            short read = apdu.receiveBytes((short) 0);

            if (read == 0) {
                throwException(ISO7816.SW_UNKNOWN);
            }

            if (curRead > (short) (bufferMem.length - read)) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            Util.arrayCopyNonAtomic(buffer, (short) 0,
                    bufferMem, (short) (curRead + chainOff), read);
            curRead = (short) (curRead + read);
        }

        if (curRead > lc) {
            tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
            throwException(ISO7816.SW_WRONG_LENGTH);
        }

        if (!apdu.isCommandChainingCLA()) {
            tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
        }
    }

    /**
     * Implements the core FIDO2 CTAP2 makeCredential API
     *
     * @param apdu Request/response object
     * @param lc Length of the request, as sent by the platform
     * @param readIdx Read index into the request buffer
     */
    private void makeCredential(APDU apdu, short lc, short readIdx) {
        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if ((bufferMem[readIdx] & 0xF0) != 0xA0) { // short-entry-count map
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short numParameters = (short) (bufferMem[readIdx++] & 0x0F);
        if (numParameters < 4) { // There's no valid makeCredential call with fewer than four params
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (bufferMem[readIdx++] != 0x01) { // clientDataHash
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (bufferMem[readIdx] == 0x58) {
            // one-byte length, then bytestr
            if (bufferMem[++readIdx] != CLIENT_DATA_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short clientDataHashIdx = (short) (readIdx + 1);
        readIdx += CLIENT_DATA_HASH_LEN + 1; // we checked above this is indeed the length of the client data hash
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (bufferMem[readIdx++] != 0x02) { // rp
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = 0;
        readIdx = consumeMapAndGetID(apdu, readIdx, lc);
        short rpIdIdx = tempShorts[IDX_TEMP_BUF_IDX_STORAGE];
        short rpIdLen = tempShorts[IDX_TEMP_BUF_IDX_LEN];

        if (bufferMem[readIdx++] != 0x03) { // user
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = 0;
        readIdx = consumeMapAndGetID(apdu, readIdx, lc);
        short userIdIdx = tempShorts[IDX_TEMP_BUF_IDX_STORAGE];
        short userIdLen = tempShorts[IDX_TEMP_BUF_IDX_LEN];
        if (userIdLen > MAX_USER_ID_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }

        if (bufferMem[readIdx++] != 0x04) { // pubKeyCredParams
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        byte pubKeyCredParamsType = bufferMem[readIdx++];
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if ((pubKeyCredParamsType & 0xF0) != 0x80) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        // We only support one algorithm, so let's find that one.
        boolean foundES256 = false;
        tempBools[IDX_RESET_FOUND_KEY_MATCH] = false;
        short numPubKeys = (short)(pubKeyCredParamsType & 0x0F);
        for (short i = 0; i < numPubKeys; i++) {
            readIdx = checkIfPubKeyBlockSupported(apdu, readIdx, lc);
            if (tempBools[IDX_RESET_FOUND_KEY_MATCH]) {
                foundES256 = true;
                break;
            }
        }

        if (!foundES256) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        boolean hmacSecretEnabled = false;
        byte credProtectLevel = 0;
        boolean pinAuthSuccess = false;

        defaultOptions();

        short excludeListStartIdx = -1;
        short numExcludeListEntries = 0;

        // Consume any remaining parameters
        byte lastMapKey = 0x04;
        for (short i = 4; i < numParameters; i++) {
            if (bufferMem[readIdx] <= lastMapKey) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            lastMapKey = bufferMem[readIdx];

            if (bufferMem[readIdx] == 0x05) { // excludeList
                short excludeListTypeVal = ub(bufferMem[(short)(readIdx + 1)]);
                if (excludeListTypeVal < 0x80 || excludeListTypeVal > 0x97) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }

                numExcludeListEntries = (short)(excludeListTypeVal - 0x80);
                excludeListStartIdx = (short)(readIdx + 2);
            } else if (bufferMem[readIdx] == 0x06) { // extensions
                if ((bufferMem[++readIdx] & 0xA0) != 0xA0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                short numExtensions = (short) (bufferMem[readIdx++] & 0x0F);
                for (short j = 0; j < numExtensions; j++) {
                    if (bufferMem[readIdx] < 0x61 || bufferMem[readIdx] > 0x77) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                    short sLen = (short) (bufferMem[readIdx] - 0x60);
                    readIdx++;
                    if (readIdx >= (short)(lc - sLen)) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                    }
                    if (sLen == HMAC_SECRET_EXTENSION_ID.length &&
                            Util.arrayCompare(bufferMem, readIdx,
                                    HMAC_SECRET_EXTENSION_ID, (short) 0, sLen) == 0) {
                        readIdx += sLen;
                        if (bufferMem[readIdx] != (byte) 0xF5 && bufferMem[readIdx] != (byte) 0xF4) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        }
                        hmacSecretEnabled = bufferMem[readIdx++] == (byte) 0xF5;
                    } else if (sLen == CRED_PROTECT_EXTENSION_ID.length &&
                                Util.arrayCompare(bufferMem, readIdx,
                                        CRED_PROTECT_EXTENSION_ID, (short) 0, sLen) == 0) {
                        readIdx += sLen;
                        credProtectLevel = bufferMem[readIdx++];
                        if (credProtectLevel != 0x01 && credProtectLevel != 0x02 && credProtectLevel != 0x03) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                        }
                    } else {
                        readIdx += sLen;
                        readIdx = consumeAnyEntity(apdu, readIdx, lc);
                        if (readIdx >= lc) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                        }
                    }
                }
                continue;
            } else if (bufferMem[readIdx] == 0x07) { // options
                readIdx++;
                readIdx = processOptionsMap(apdu, readIdx, lc);
                continue;
            } else if (bufferMem[readIdx] == 0x08) { // pinAuth
                readIdx = verifyPinAuth(apdu, ++readIdx, clientDataHashIdx);
                pinAuthSuccess = true;
                continue;
            } else if (bufferMem[readIdx] == 0x09) { // pinProtocol
                if (bufferMem[++readIdx] != 0x01) { // PIN protocol version 1
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                }
                continue;
            } else {
                readIdx++;
            }

            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            readIdx = consumeAnyEntity(apdu, readIdx, lc);
        }

        if (!pinAuthSuccess) {
            if (pinSet) {
                // PIN is set, but no PIN-auth option was provided
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
            }
            if (!ALLOW_RESIDENT_KEY_CREATION_WITHOUT_PIN && tempBools[IDX_OPTION_RK]) {
                // Don't allow storing resident keys without a PIN set
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
            }
        }
        loadWrappingKeyIfNoPIN();

        final short scratchRPIDHashOffset = scratchAlloc(RP_HASH_LEN);
        short digested = sha256.doFinal(bufferMem, rpIdIdx, rpIdLen, scratch, scratchRPIDHashOffset);
        if (digested != RP_HASH_LEN) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // Check excludeList. This is deferred to here so it's after we check PIN auth...
        if (numExcludeListEntries > 0) {
            short excludeListCredSpace = scratchAlloc(CREDENTIAL_ID_LEN);

            short excludeReadIdx = excludeListStartIdx;
            for (short excludeListIdx = 0; excludeListIdx < numExcludeListEntries; excludeListIdx++) {
                tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = 0;
                excludeReadIdx = consumeMapAndGetID(apdu, excludeReadIdx, lc);
                short credIdIdx = tempShorts[IDX_TEMP_BUF_IDX_STORAGE];
                short credIdLen = tempShorts[IDX_TEMP_BUF_IDX_LEN];
                if (credIdIdx == 0) {
                    // Not having an ID in here means it's invalid
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                }
                if (credIdLen != CREDENTIAL_ID_LEN) {
                    // ruh-roh, the exclude list has bogus stuff in it...
                    // it could be a credential ID from some OTHER authenticator, so ignore it.
                    continue;
                }

                if (checkCredential(bufferMem, credIdIdx, credIdLen,
                        scratch, scratchRPIDHashOffset,
                        scratch, excludeListCredSpace)) {
                    // This cred decodes valid and is for the given RPID - fail early.
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }

            scratchRelease(CREDENTIAL_ID_LEN);
        }

        // Done getting params - make a keypair. You know, what we're supposed to do in this function?
        // Well, we're getting to it, only 150 lines in.
        // We sometimes reset the private key, which clears its curve data, so reset that here
        P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
        ecKeyPair.genKeyPair();

        final short scratchPublicKeyOffset = scratchAlloc((short) (KEY_POINT_LENGTH * 2 + 1));
        final short wLen = ((ECPublicKey) ecKeyPair.getPublic()).getW(scratch, scratchPublicKeyOffset);
        if (scratch[scratchPublicKeyOffset] != 0x04) {
            // EC algorithm returned a compressed point... we can't decode that...
            throwException(ISO7816.SW_UNKNOWN);
        }
        if (wLen != 2 * KEY_POINT_LENGTH + 1) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // From here on down, privateScratch will contain the new credential ID
        encodeCredentialID(apdu, (ECPrivateKey) ecKeyPair.getPrivate(), scratch, scratchRPIDHashOffset);

        // if we're making a resident key, we need to, you know, save that for later
        if (tempBools[IDX_OPTION_RK]) {
            short decodedCredOffset = scratchAlloc(CREDENTIAL_ID_LEN);
            short rkSpecificScratchAlloc = CREDENTIAL_ID_LEN;

            final short scratchUserIdOffset = scratchAlloc(MAX_USER_ID_LENGTH);
            rkSpecificScratchAlloc += MAX_USER_ID_LENGTH;

            final short scratchRpIdOffset = scratchAlloc(MAX_RESIDENT_RP_ID_LENGTH);
            rkSpecificScratchAlloc += MAX_RESIDENT_RP_ID_LENGTH;
            rpIdLen = truncateRPId(bufferMem, rpIdIdx, rpIdLen,
                    scratch, scratchRpIdOffset);

            short targetRKSlot = -1;
            boolean foundMatchingRK = false;
            boolean foundRPMatchInRKs = false;
            for (short i = 0; i < NUM_RESIDENT_KEY_SLOTS; i++) {
                if (!residentKeyValidity[i]) {
                    if (targetRKSlot == -1) {
                        targetRKSlot = i;
                    }
                    // Don't decode empty/non-valid credentials
                    continue;
                }

                if (checkCredential(
                        residentKeyData, (short) (i * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                        scratch, scratchRPIDHashOffset,
                        scratch, decodedCredOffset)) {
                    // This credential matches the RP we're looking at.
                    foundRPMatchInRKs = true;

                    // ... but it might not match the user ID we're requesting...
                    if (userIdLen == residentKeyUserIdLengths[i]) {
                        // DECRYPT the encrypted user ID we stored for this RK, so we can compare
                        symmetricUnwrapper.doFinal(
                                residentKeyUserIds, (short) (i * MAX_USER_ID_LENGTH), MAX_USER_ID_LENGTH,
                                scratch, scratchUserIdOffset
                        );

                        if (Util.arrayCompare(
                                bufferMem, userIdIdx,
                                scratch, scratchUserIdOffset, userIdLen
                                ) == 0) {
                            // ... this credential is a perfect match - overwrite it
                            foundMatchingRK = true;
                            targetRKSlot = i;
                            break;
                        }
                    }
                }
            }

            if (targetRKSlot == -1) {
                // We're entirely full up...
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
            }

            // Stow the new credential in the slot we chose earlier
            // we will need the zero-padded user ID
            Util.arrayCopyNonAtomic(bufferMem, userIdIdx, scratch, scratchUserIdOffset, userIdLen);
            if (userIdLen < MAX_USER_ID_LENGTH) {
                Util.arrayFillNonAtomic(scratch, (short)(scratchUserIdOffset + userIdLen),
                        (short)(MAX_USER_ID_LENGTH - userIdLen), (byte) 0x00);
            }

            JCSystem.beginTransaction();
            Util.arrayCopy(privateScratch, (short) 0,
                    residentKeyData, (short) (targetRKSlot * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN);
            residentKeyUserIdLengths[targetRKSlot] = (byte) userIdLen;
            symmetricWrapper.doFinal(scratch, scratchUserIdOffset, MAX_USER_ID_LENGTH,
                    residentKeyUserIds, (short) (targetRKSlot * MAX_USER_ID_LENGTH));
            residentKeyRPIdLengths[targetRKSlot] = (byte) rpIdLen;
            symmetricWrapper.doFinal(scratch, scratchRpIdOffset, MAX_RESIDENT_RP_ID_LENGTH,
                    residentKeyRPIds, (short) (targetRKSlot * MAX_RESIDENT_RP_ID_LENGTH));
            symmetricWrapper.doFinal(scratch, (short)(scratchPublicKeyOffset + 1), (short)(KEY_POINT_LENGTH * 2),
                    residentKeyPublicKeys, (short) (targetRKSlot * KEY_POINT_LENGTH * 2));
            residentKeyValidity[targetRKSlot] = true;
            if (!foundMatchingRK) {
                // We're filling an empty slot
                numResidentCredentials++;
            }
            residentKeyUniqueRP[targetRKSlot] = !foundRPMatchInRKs;
            if (!foundRPMatchInRKs) {
                numResidentRPs++;
            }
            JCSystem.commitTransaction();

            scratchRelease(rkSpecificScratchAlloc);
        }

        // OKAY! time to start actually making the credential and sending a response!
        final short CLIENT_DATA_HASH_BUF_OFFSET = scratchAlloc(CLIENT_DATA_HASH_LEN);
        Util.arrayCopyNonAtomic(bufferMem, clientDataHashIdx,
                scratch, CLIENT_DATA_HASH_BUF_OFFSET, CLIENT_DATA_HASH_LEN);

        // Everything we need is out of the input
        // We're now okay to use the whole bufferMem space to build and send our reply

        // First, preamble
        short outputLen = Util.arrayCopyNonAtomic(MAKE_CREDENTIAL_RESPONSE_PREAMBLE, (short) 0,
                bufferMem, (short) 0, (short) MAKE_CREDENTIAL_RESPONSE_PREAMBLE.length);

        // CBOR requires us to know how long authData is before we can start writing it out...
        // ... so let's calculate that
        final short adLen = getAuthDataLen(true, hmacSecretEnabled, credProtectLevel > 0);

        // DONE: set bit 0 for user present (currently always)
        // DONE: set bit 6 for attestation included (always, for a makeCredential)
        byte flags = 0x41;
        if (pinAuthSuccess) {
            // DONE: set bit 2 for user verified
            flags = (byte)(flags | 0x04);
        }
        if (hmacSecretEnabled || credProtectLevel > 0) {
            // DONE: set bit 7 for extensions
            flags = (byte)(flags | 0x80);
        }

        short adAddlBytes = writeAD(adLen, outputLen, scratch, scratchRPIDHashOffset,
                scratch, (short)(scratchPublicKeyOffset + 1), flags, hmacSecretEnabled, credProtectLevel);

        short offsetForStartOfAuthData = (short) (outputLen + adAddlBytes);
        outputLen += adLen + adAddlBytes;

        // Attestation statement
        outputLen = Util.arrayCopyNonAtomic(ATTESTATION_STATEMENT_PREAMBLE, (short) 0,
                bufferMem, outputLen, (short) ATTESTATION_STATEMENT_PREAMBLE.length);

        attester.init(ecKeyPair.getPrivate(), Signature.MODE_SIGN);
        attester.update(bufferMem, offsetForStartOfAuthData, adLen);
        short sigLength = attester.sign(scratch, CLIENT_DATA_HASH_BUF_OFFSET, CLIENT_DATA_HASH_LEN,
                bufferMem, (short) (outputLen + 1));
        if (sigLength > 256 || sigLength < 24) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        bufferMem[outputLen++] = (byte) sigLength;
        outputLen += sigLength;

        // EC key pair COULD be stored in flash (if device doesn't support transient EC privKeys), so might as
        // we clear it out here since we don't need it any more. We'll get its private key back from the credential
        // ID to use it later...
        ecKeyPair.getPrivate().clearKey();

        doSendResponse(apdu, outputLen);
    }

    /**
     * If, and only if, no PIN is set, directly initialize symmetric crypto
     * from our flash-stored wrapping key (which should be unencrypted)
     */
    private void loadWrappingKeyIfNoPIN() {
        if (!pinSet) {
            wrappingKey.setKey(wrappingKeySpace, (short) 0);

            initSymmetricCrypto();
        }
    }

    /**
     * Copies a section of a raw RP ID into a target buffer. If it is longer than the max it will be cut down.
     * If it is shorter, it will be zero-padded.
     *
     * @param rpIdBuf Buffer containing the raw RP ID
     * @param rpIdIdx Index of RP ID in the incoming buffer
     * @param rpIdLen Length of the incoming RP ID
     * @param outputBuff Output buffer into which to write truncated/padded values
     * @param outputOff Write index into output buffer
     *
     * @return Length of RP ID after padding/truncation
     */
    private short truncateRPId(byte[] rpIdBuf, short rpIdIdx, short rpIdLen, byte[] outputBuff, short outputOff) {
        // TODO: better truncation as described in CTAP2.1
        if (rpIdLen > MAX_RESIDENT_RP_ID_LENGTH) {
            rpIdLen = MAX_RESIDENT_RP_ID_LENGTH;
        }
        Util.arrayCopyNonAtomic(rpIdBuf, rpIdIdx,
                outputBuff, outputOff, rpIdLen);
        if (rpIdLen < MAX_RESIDENT_RP_ID_LENGTH) {
            Util.arrayFillNonAtomic(outputBuff, (short)(outputOff + rpIdLen),
                    (short)(MAX_RESIDENT_RP_ID_LENGTH - rpIdLen), (byte) 0x00);
        }

        return rpIdLen;
    }

    /**
     * Handspun implementation of HMAC-SHA256, to work around lack of hardware support
     *
     * @param keyBuff Buffer containing 32-byte-long private key
     * @param keyOff Offset of private key in key buffer
     * @param content Buffer containing arbitrary-length content to be HMACed
     * @param contentOff Offset of content in buffer
     * @param contentLen Length of content
     * @param outputBuff Buffer into which output should be written - must have 32 bytes available
     * @param outputOff Write index into output buffer
     */
    private void hmacSha256(byte[] keyBuff, short keyOff,
                             byte[] content, short contentOff, short contentLen,
                             byte[] outputBuff, short outputOff) {
        final short scratchAmt = (short) (contentLen + 64);
        short scratchFirst = scratchAlloc((short) 32);
        short scratchSecond = scratchAlloc((short) 32);
        short scratchMessage = scratchAlloc(contentLen);

        // first half: put key + 32x 0x36 + content into the buffer
        for (short i = 0; i < 32; i++) {
            scratch[(short) (scratchFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x36)); // ipad
        }
        Util.arrayFillNonAtomic(scratch, scratchSecond, (short) 32, (byte) 0x36);

        Util.arrayCopyNonAtomic(content, contentOff,
                scratch, scratchMessage, contentLen);

        sha256.doFinal(scratch, scratchFirst, (short)(64 + contentLen),
                scratch, scratchMessage);

        // second half: put key + 32x 0x5c into buffer, then hash into spot adjacent to previous hash
        for (short i = 0; i < 32; i++) {
            scratch[(short) (scratchFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x5c)); // opad
        }
        Util.arrayFillNonAtomic(scratch, scratchSecond, (short) 32, (byte) 0x5c);

        sha256.doFinal(scratch, scratchFirst, (short) 96, outputBuff, outputOff);

        scratchRelease(scratchAmt);
    }

    /**
     * Uses the currently-set pinToken to hash some data and compare against a verification value
     *
     * @param apdu Request/response object
     * @param content Buffer containing content to HMAC using the pinToken
     * @param contentIdx Index of content in given buffer
     * @param contentLen Length of content
     * @param checkAgainst Buffer containing "correct" hash we're looking for
     * @param checkIdx Index of correct hash in corresponding buffer
     */
    private void checkPinTokenProtocolOne(APDU apdu, byte[] content, short contentIdx, short contentLen,
                                          byte[] checkAgainst, short checkIdx) {
        short scratchAmt = (short) 32;
        short scratchOff = scratchAlloc(scratchAmt);

        // Pad pinToken to 32 bytes for HMAC-ing
        Util.arrayCopyNonAtomic(pinToken, (short) 0,
                scratch, scratchOff, (short) 16);
        Util.arrayFillNonAtomic(scratch, (short)(scratchOff + 16), (short) 16, (byte) 0x00);

        hmacSha256(scratch, scratchOff,
                   content, contentIdx, contentLen,
                   scratch, scratchOff);

        // Compare only the first 16 bytes, because that's the protocol
        if (Util.arrayCompare(
                scratch, scratchOff,
                checkAgainst, checkIdx, (short) 16
        ) != 0) {
            // PIN token incorrect...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        scratchRelease(scratchAmt);
    }

    /**
     * Consumes an incoming pinAuth block and checks it matches our set pinToken.
     *
     * @param apdu Request/response object
     * @param readIdx Read index into bufferMem pointing to a 16-byte array (pinAuth)
     * @param clientDataHashIdx Index in bufferMem of the hash of the clientData object, as given by the platform
     *
     * @return New read index into bufferMem after consuming the pinAuth options block
     */
    private short verifyPinAuth(APDU apdu, short readIdx, short clientDataHashIdx) {
        if (bufferMem[readIdx++] != 0x50) { // byte array, 16 bytes long
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        checkPinTokenProtocolOne(apdu, bufferMem, clientDataHashIdx, CLIENT_DATA_HASH_LEN,
                bufferMem, readIdx);

        readIdx += 16;

        return readIdx;
    }

    /**
     * Consumes a CBOR block of public key data, and checks if it represents a supported algorithm.
     * After call, tempShorts[IDX_RESET_FOUND_KEY_MATCH] will be true if the key is compatible. It should be set
     * to false prior to call
     *
     * @param apdu Request/response object
     * @param readIdx Read index into bufferMem
     * @param lc Length of incoming request, as sent by the platform
     *
     * @return New read index into bufferMem after consuming public key block
     */
    private short checkIfPubKeyBlockSupported(APDU apdu, short readIdx, short lc) {
        if (bufferMem[readIdx++] != (byte) 0xA2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (bufferMem[readIdx++] != 0x63) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx >= (short)(lc-4)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (bufferMem[readIdx++] != 'a' || bufferMem[readIdx++] != 'l' || bufferMem[readIdx++] != 'g') {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        byte algIntType = bufferMem[readIdx++];
        if (algIntType == 0x26) { // ES256...
            tempBools[IDX_RESET_FOUND_KEY_MATCH] = true;
        } else if (algIntType == 0x38 || algIntType == 0x18) {
            readIdx++;
        } else if (algIntType == 0x39 || algIntType == 0x19) {
            readIdx += 2;
        } else if (!(algIntType >= (byte)0x20 && algIntType <= (byte)0x37)
            && !(ub(algIntType) >= 0x00 && algIntType <= (byte) 0x17)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        // Skip "type" val
        if ((bufferMem[readIdx] & 0xF0) != 0x60) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short valLen = (short) (bufferMem[readIdx] & 0x0F);
        readIdx += valLen + 1;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if ((bufferMem[readIdx] & 0xF0) != 0x60) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short typeValLen = (short) (bufferMem[readIdx] & 0x0F);
        readIdx += typeValLen + 1;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        return readIdx;
    }

    /**
     * Write the portions of an authData block that are used for both makeCredential and getAssertion
     *
     * @param adLen Length of the overall AD block
     * @param writeIdx Write index into bufferMem
     * @param flags CTAP2 "flags" byte value
     * @param rpIdBuffer Buffer containing a hash of the RP ID
     * @param rpIdOffset Offset of the RP ID hash in the given buffer
     *
     * @return New write index into bufferMem after serializing AD block
     */
    private short writeADBasic(short adLen, short writeIdx, byte flags, byte[] rpIdBuffer, short rpIdOffset) {
        short adAddlBytes;

        if (adLen < 24) {
            bufferMem[writeIdx++] = (byte)(0x50 + adLen);
            adAddlBytes = 1;
        } else if (adLen < 256) {
            bufferMem[writeIdx++] = 0x58; // byte string, with one-byte length
            bufferMem[writeIdx++] = (byte) adLen;
            adAddlBytes = 2;
        } else {
            bufferMem[writeIdx++] = 0x59; // byte string, with two-byte length
            writeIdx = Util.setShort(bufferMem, writeIdx, adLen);
            adAddlBytes = 3;
        }

        // RPID hash
        writeIdx = Util.arrayCopyNonAtomic(rpIdBuffer, rpIdOffset, bufferMem, writeIdx, RP_HASH_LEN);

        bufferMem[writeIdx++] = flags; // flags

        // counter
        writeIdx = encodeCounter(bufferMem, writeIdx);
        incrementCounter();

        return adAddlBytes;
    }

    private short encodeCounter(byte[] buf, short off) {
        buf[off++] = counter[0];
        buf[off++] = counter[1];
        buf[off++] = counter[2];
        buf[off++] = counter[3];
        return off;
    }

    /**
     * Writes an authenticated data block into the output buffer.
     * Before call, privateScratch must contain the credential ID
     *
     * @param adLen             total length of the AD block
     * @param writeIdx          write index into the response buffer
     * @param rpIdHashBuffer    buffer containing RP ID hash
     * @param rpIdHashOffset    offset of the RP ID hash in the buffer
     * @param pubKeyBuffer      buffer containing the PUBLIC key
     * @param pubKeyOffset      offset of the public key in the corresponding buffer
     * @param flags             flags byte to pack into authData object
     * @param hmacSecretEnabled true if the HMAC secret extension is in use
     * @param credProtectLevel  Integer (0-3) for level of credProtect enabled; 0 to disable
     *
     * @return new write index into output buffer
     */
    private short writeAD(short adLen, short writeIdx, byte[] rpIdHashBuffer, short rpIdHashOffset,
                          byte[] pubKeyBuffer, short pubKeyOffset, byte flags,
                          boolean hmacSecretEnabled, byte credProtectLevel) {
        short adAddlBytes = writeADBasic(adLen, writeIdx, flags, rpIdHashBuffer, rpIdHashOffset);
        writeIdx += getAuthDataLen(false, hmacSecretEnabled, credProtectLevel > 0) + adAddlBytes;

        // aaguid
        writeIdx = Util.arrayCopyNonAtomic(aaguid, (short) 0, bufferMem, writeIdx, (short) aaguid.length);

        // credential ID length
        writeIdx = Util.setShort(bufferMem, writeIdx, CREDENTIAL_ID_LEN);

        writeIdx = Util.arrayCopyNonAtomic(privateScratch, (short) 0,
                bufferMem, writeIdx, CREDENTIAL_ID_LEN);

        // Public key
        writeIdx = Util.arrayCopyNonAtomic(PUBLIC_KEY_ALG_PREAMBLE, (short) 0,
                bufferMem, writeIdx, (short) PUBLIC_KEY_ALG_PREAMBLE.length);
        writeIdx = writePubKey(writeIdx, pubKeyBuffer, pubKeyOffset);

        short numExtensions = 0;
        if (hmacSecretEnabled) {
            numExtensions++;
        }
        if (credProtectLevel > 0) {
            numExtensions++;
        }

        if (numExtensions > 0) {
            bufferMem[writeIdx++] = (byte)(0xA0 + numExtensions);
        }

        if (hmacSecretEnabled) {
            bufferMem[writeIdx++] = (byte) (96 + HMAC_SECRET_EXTENSION_ID.length);
            writeIdx = Util.arrayCopy(HMAC_SECRET_EXTENSION_ID, (short) 0,
                    bufferMem, writeIdx, (short)HMAC_SECRET_EXTENSION_ID.length);
            bufferMem[writeIdx++] = (byte) 0xF5; // boolean true
        }

        if (credProtectLevel > 0) {
            bufferMem[writeIdx++] = (byte) (96 + CRED_PROTECT_EXTENSION_ID.length);
            writeIdx = Util.arrayCopy(CRED_PROTECT_EXTENSION_ID, (short) 0,
                    bufferMem, writeIdx, (short)CRED_PROTECT_EXTENSION_ID.length);
            bufferMem[writeIdx++] = credProtectLevel;
        }

        return adAddlBytes;
    }

    /**
     * Builds a credential ID into privateScratch
     *
     * @param apdu Request/response object
     * @param privKeyBuffer Buffer containing private key
     * @param privateKeyOffset Index of private key start in input buffer
     * @param privKeyLen Length of private key
     * @param rpIdHashBuffer Buffer containing hash of RP ID
     * @param rpIdHashOffset Index of RP ID hash in corresponding buffer
     */
    private void encodeCredentialID(APDU apdu, ECPrivateKey privKey,
                                    byte[] rpIdHashBuffer, short rpIdHashOffset) {
        final short scratchOff = scratchAlloc(KEY_POINT_LENGTH);
        final short sLen = privKey.getS(scratch, scratchOff);
        if (sLen != KEY_POINT_LENGTH) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // credential ID
        // Encrypt: PrivKey || rpIdHash
        // 32 + 32 = 64 bytes max
        short encryptedBytes = symmetricWrapper.update(scratch, scratchOff, sLen,
                privateScratch, (short) 0);
        encryptedBytes += symmetricWrapper.doFinal(rpIdHashBuffer, rpIdHashOffset, RP_HASH_LEN,
                privateScratch, encryptedBytes);
        if (encryptedBytes > CREDENTIAL_ID_LEN) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }

        scratchRelease(KEY_POINT_LENGTH);
    }

    /**
     * Pack an EC public key into the output buffer
     *
     * @param outputLen The current index in the output buffer (begin writing here)
     * @param pubKeyBuffer A buffer containing the public key to be written in the format X || Y
     * @param pubKeyOffset An index pointing to the X-coordinate of the public key
     *
     * @return New index in the output buffer after writes
     */
    private short writePubKey(short outputLen, byte[] pubKeyBuffer, short pubKeyOffset) {
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, pubKeyOffset,
                bufferMem, outputLen, KEY_POINT_LENGTH);
        bufferMem[outputLen++] = 0x22; // map key: y-coordinate
        bufferMem[outputLen++] = 0x58; // byte string with one-byte length to follow
        bufferMem[outputLen++] = (byte) KEY_POINT_LENGTH;
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, (short) (pubKeyOffset + KEY_POINT_LENGTH),
                bufferMem, outputLen, KEY_POINT_LENGTH);
        return outputLen;
    }

    /**
     * Calculates the length of an auth data segment
     *
     * @param includeAttestedKey If true, includes attestion data - for makeCredential
     * @param useHmacSecret If true, includes the bytes for the hmac-secret extension
     *
     * @return The number of bytes in the authentication data segment
     */
    private short getAuthDataLen(boolean includeAttestedKey, boolean useHmacSecret, boolean useCredProtect) {
        short basicLen = (short) (RP_HASH_LEN + // RP ID hash
                1 + // flags byte
                4 // counter
        );

        if (!includeAttestedKey) {
            return basicLen;
        }

        return (short) (basicLen +
                (short) aaguid.length + // aaguid
                2 + // credential ID length
                CREDENTIAL_ID_LEN + // credential ID
                PUBLIC_KEY_ALG_PREAMBLE.length + // preamble for cred public key
                KEY_POINT_LENGTH + // x-point
                3 + // CBOR bytes to introduce the y-point
                KEY_POINT_LENGTH + // y-point
                (useCredProtect || useHmacSecret ? 1 : 0) + // extension data intro
                (useHmacSecret ? 2 + HMAC_SECRET_EXTENSION_ID.length : 0) + // extension data
                (useCredProtect ? 2 + CRED_PROTECT_EXTENSION_ID.length : 0) // more extension data
        );
    }

    /**
     * Handles a CTAP2 getAssertion API call
     *
     * @param apdu The request/response object
     * @param lc The declared request length
     * @param readIdx The current read offset into buffer memory
     */
    private void getAssertion(APDU apdu, short lc, short readIdx) {
        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if ((bufferMem[readIdx] & 0xF0) != 0xA0) { // map with relatively few entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short numParams = (short) (bufferMem[readIdx++] & 0x0F);
        if (numParams < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (bufferMem[readIdx++] != 0x01) { // rpId
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short rpIdLen = 0;
        if (bufferMem[readIdx] == 0x78) { // one-byte length
            readIdx++;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            rpIdLen = bufferMem[readIdx++];
        } else if (bufferMem[readIdx] >= 0x61 && bufferMem[readIdx] < 0x78) { // zero-byte packed length
            rpIdLen = (short)(bufferMem[readIdx] - 0x60);
            readIdx++;
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short rpIdIdx = readIdx;
        readIdx += rpIdLen;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (bufferMem[readIdx++] != 0x02) { // clientDataHash
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        short clientDataHashLen = 0;
        if (bufferMem[readIdx] == 0x58) {
            readIdx++;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            clientDataHashLen = bufferMem[readIdx++];
        } else if (bufferMem[readIdx] >= 0x51 && bufferMem[readIdx] < 0x58) {
            clientDataHashLen = (short)(bufferMem[readIdx] - 0x60);
            readIdx++;
        }
        short clientDataHashIdx = readIdx;
        readIdx += clientDataHashLen;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short scratchRPIDHashIdx = scratchAlloc(RP_HASH_LEN);
        short totalScratchAlloc = RP_HASH_LEN;

        // Scratch: rpIdHash || pubKeyCredData || clientDataHash
        short digested = sha256.doFinal(bufferMem, rpIdIdx, rpIdLen, scratch, scratchRPIDHashIdx);
        if (digested != RP_HASH_LEN) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        short startOfMatchingPubKeyCredData = (short) -1;
        byte[] matchingPubKeyBuffer = bufferMem;
        short matchingPubKeyCredDataLen = 0;
        short rkMatch = -1;
        short allowListIdx = -1;

        short paramsRead = 2;
        if (bufferMem[readIdx] == 0x03) { // allowList
            readIdx++;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            // We need to defer this until after we do PIN processing
            allowListIdx = readIdx;
            paramsRead++;
            readIdx = consumeAnyEntity(apdu, readIdx, lc);
        }

        short hmacSecretBytes = 0;
        short hmacSecretDataIdx = -1;

        defaultOptions();
        boolean pinAuthSuccess = false;

        // Consume any remaining parameters
        byte lastMapKey = 0x03; // Doesn't matter if it's actually 0x02 or whatever, we just need them in order
        for (short i = paramsRead; i < numParams; i++) {
            byte mapKey = bufferMem[readIdx++];
            if (mapKey <= lastMapKey) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            lastMapKey = mapKey;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            if (mapKey == 0x04) { // extensions
                if ((bufferMem[readIdx] & 0xA0) != 0xA0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }

                short mapEntries = (short) (bufferMem[readIdx++] & 0x0F);
                for (short j = 0; j < mapEntries; j++) {
                    if ((bufferMem[readIdx] & 0x60) != 0x60) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                    short keyLength = (short)(bufferMem[readIdx++] & 0x0F);
                    if (keyLength != HMAC_SECRET_EXTENSION_ID.length || Util.arrayCompare(bufferMem, readIdx,
                            HMAC_SECRET_EXTENSION_ID, (short) 0, (short) HMAC_SECRET_EXTENSION_ID.length) != 0) {
                        // Extension that is NOT hmac-secret: ignore it
                        readIdx = consumeAnyEntity(apdu, (short)(readIdx + keyLength), lc);
                        continue;
                    }

                    readIdx += keyLength;

                    // We've got a case of hmac-secret extension params!
                    // store the index and revisit it later, when we've decoded the keys
                    hmacSecretDataIdx = readIdx;
                    readIdx = consumeAnyEntity(apdu, readIdx, lc);
                }

                continue;
            } else if (mapKey == 0x05) { // options
                readIdx = processOptionsMap(apdu, readIdx, lc);
                continue;
            } else if (mapKey == 0x06) { // pinAuth
                readIdx = verifyPinAuth(apdu, readIdx, clientDataHashIdx);
                pinAuthSuccess = true;
                continue;
            } else if (mapKey == 0x07) { // pinProtocol
                if (bufferMem[readIdx++] != 0x01) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
                continue;
            }

            readIdx = consumeAnyEntity(apdu, readIdx, lc);
        }

        if (pinSet && pinAuthSuccess && tempBools[IDX_OPTION_UV]) {
            // When a PIN is set and provided, the "uv" input option MUST NOT be set.
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
        }

        // Report PIN-validation failures before we report lack of matching creds
        if (pinSet && (!tempBools[IDX_RESET_PIN_PROVIDED] || !pinAuthSuccess)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
        }

        loadWrappingKeyIfNoPIN();

        if (allowListIdx != -1) {
            short blockReadIdx = allowListIdx;
            if (((byte)(bufferMem[blockReadIdx] & 0xF0)) != (byte)0x80) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            short numPubKeysToCheck = (short) (bufferMem[blockReadIdx++] & 0x0F);
            if (blockReadIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            for (short i = 0; i < numPubKeysToCheck; i++) {
                tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = 0;
                short beforeReadIdx = blockReadIdx;
                blockReadIdx = consumeMapAndGetID(apdu, blockReadIdx, lc);
                short pubKeyIdx = tempShorts[IDX_TEMP_BUF_IDX_STORAGE];
                short pubKeyLen = tempShorts[IDX_TEMP_BUF_IDX_LEN];

                if (startOfMatchingPubKeyCredData == (short) -1) {
                    boolean matches = checkCredential(bufferMem, pubKeyIdx, pubKeyLen, scratch, scratchRPIDHashIdx,
                            privateScratch, (short) 0);
                    if (matches) {
                        startOfMatchingPubKeyCredData = beforeReadIdx;
                        matchingPubKeyCredDataLen = (short) (blockReadIdx - startOfMatchingPubKeyCredData);
                    }
                }
            }
        }

        if (startOfMatchingPubKeyCredData == -1) {
            // Scan resident keys for match
            for (short i = 0; i < NUM_RESIDENT_KEY_SLOTS; i++) {
                if (!residentKeyValidity[i]) {
                    continue;
                }

                if (checkCredential(residentKeyData, (short) (i * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                        scratch, scratchRPIDHashIdx,
                        privateScratch, (short) 0)) {
                    // Got a resident key hit!
                    matchingPubKeyBuffer = residentKeyData;
                    startOfMatchingPubKeyCredData = (short)(i * CREDENTIAL_ID_LEN);
                    matchingPubKeyCredDataLen = CREDENTIAL_ID_LEN;
                    rkMatch = i;
                    break;
                }
            }
        }

        if (startOfMatchingPubKeyCredData == (short) -1) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        P256Constants.setCurve(ecPrivateKey);
        ecPrivateKey.setS(privateScratch, (short) 0, (short) 32);
        attester.init(ecPrivateKey, Signature.MODE_SIGN);

        // HMAC will clobber privateScratch, so it needs to be below the private key setup above
        short hmacScratchOffset = scratchAlloc((short) 64);
        totalScratchAlloc += 64;
        if (hmacSecretDataIdx > -1) {
            hmacSecretBytes = computeHMACSecret(apdu, hmacSecretDataIdx, lc, scratch, hmacScratchOffset);
        }

        short scratchPubKeyCredIdx = scratchAlloc(matchingPubKeyCredDataLen);
        totalScratchAlloc += matchingPubKeyCredDataLen;
        short scratchClientDataHashIdx = scratchAlloc(clientDataHashLen);
        totalScratchAlloc += clientDataHashLen;
        Util.arrayCopyNonAtomic(matchingPubKeyBuffer, startOfMatchingPubKeyCredData, scratch, scratchPubKeyCredIdx, matchingPubKeyCredDataLen);
        Util.arrayCopyNonAtomic(bufferMem, clientDataHashIdx, scratch, scratchClientDataHashIdx, clientDataHashLen);

        // RESPONSE BELOW HERE

        short outputLen = 0;
        bufferMem[outputLen++] = FIDOConstants.CTAP2_OK;
        bufferMem[outputLen++] = rkMatch > -1 ? (byte) 0xA4 : (byte) 0xA3; // map with four or three entries
        bufferMem[outputLen++] = 0x01; // map key: credential

        // credential
        if (rkMatch > -1) {
            // Resident keys need CBOR wrapping...
            outputLen = Util.arrayCopyNonAtomic(SINGLE_ID_MAP_PREAMBLE, (short) 0,
                    bufferMem, outputLen, (short) SINGLE_ID_MAP_PREAMBLE.length);
            bufferMem[outputLen++] = 0x58; // byte array with one-byte length
            bufferMem[outputLen++] = (byte) matchingPubKeyCredDataLen;
        }
        outputLen = Util.arrayCopyNonAtomic(scratch, scratchPubKeyCredIdx, bufferMem, outputLen, matchingPubKeyCredDataLen);

        bufferMem[outputLen++] = 0x02; // map key: authData

        byte flags = tempBools[IDX_OPTION_UP] ? (byte) 0x01 : 0x00;
        if (pinAuthSuccess) {
            flags = (byte)(flags | 0x04);
        }

        short adLen = getAuthDataLen(false, false, false);
        short extensionDataLen = 0;
        if (hmacSecretBytes > 0) {
            extensionDataLen = (short) (
                    hmacSecretBytes +
                    4 + // CBOR overhead bytes
                    HMAC_SECRET_EXTENSION_ID.length
            );
            flags = (byte)(flags | 0x80);
        }

        // authData (no attestation...)
        short adAddlBytes = writeADBasic((short) (adLen + extensionDataLen), outputLen, flags, scratch, scratchRPIDHashIdx);

        short startOfAD = (short) (outputLen + adAddlBytes);

        outputLen = (short) (startOfAD + adLen);
        short beforeExtensionOutputLen = outputLen;
        if (hmacSecretBytes > 0) {
            bufferMem[outputLen++] = (byte) 0xA1; // map with one item
            bufferMem[outputLen++] = 0x6B; // string: eleven bytes long
            outputLen = Util.arrayCopyNonAtomic(HMAC_SECRET_EXTENSION_ID, (short) 0,
                    bufferMem, outputLen, (short) HMAC_SECRET_EXTENSION_ID.length);
            bufferMem[outputLen++] = 0x58; // byte string: one-byte length
            bufferMem[outputLen++] = (byte) hmacSecretBytes;
            outputLen = Util.arrayCopyNonAtomic(scratch, hmacScratchOffset,
                    bufferMem, outputLen, hmacSecretBytes);
        }
        if ((short)(outputLen - beforeExtensionOutputLen) != extensionDataLen) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // signature
        bufferMem[outputLen++] = 0x03; // map key: signature
        bufferMem[outputLen++] = 0x58; // one-byte length
        attester.update(bufferMem, startOfAD, (short) (adLen + extensionDataLen));
        short sigLength = attester.sign(scratch, scratchClientDataHashIdx, clientDataHashLen,
                bufferMem, (short) (outputLen + 1));
        if (sigLength > 256 || sigLength < 24) {
            throwException(ISO7816.SW_UNKNOWN);
        }
        bufferMem[outputLen] = (byte) sigLength;
        outputLen += sigLength + 1;
        // After the signature, we are done with the credential private key we loaded.
        // It might be stored in flash, so let's clear that out.
        ecPrivateKey.clearKey();

        scratchRelease(totalScratchAlloc);
        short rkUIDOffset = scratchAlloc((short)(MAX_USER_ID_LENGTH + 1));

        if (rkMatch > -1) {
            // Pack the user ID from the resident key into a buffer, after decrypting it
            symmetricUnwrapper.doFinal(residentKeyUserIds, (short) (rkMatch * MAX_USER_ID_LENGTH), MAX_USER_ID_LENGTH,
                    scratch, rkUIDOffset);
            short uidLen = ub(residentKeyUserIdLengths[rkMatch]);

            bufferMem[outputLen++] = 0x04; // map key: user
            outputLen = Util.arrayCopyNonAtomic(SINGLE_ID_MAP_PREAMBLE, (short) 0,
                    bufferMem, outputLen, (short) SINGLE_ID_MAP_PREAMBLE.length);
            outputLen = encodeIntLen(outputLen, uidLen, true);
            outputLen = Util.arrayCopyNonAtomic(scratch, rkUIDOffset,
                    bufferMem, outputLen, uidLen);
        }

        doSendResponse(apdu, outputLen);
    }

    /**
     * Pack the length of a string or byte array as CBOR into bufferMem
     *
     * @param writeIdx write index into bufferMem
     * @param v length value to be packed
     * @param byteString if true, value is the length of a byte string; if false, character string
     *
     * @return new write index after packing
     */
    private short encodeIntLen(short writeIdx, short v, boolean byteString) {
        if (v < 24) {
            bufferMem[writeIdx++] = (byte)((byteString ? 0x40 : 0x60) + v); // string with inline length
        } else {
            bufferMem[writeIdx++] = (byte)(byteString ? 0x58 : 0x78); // string: one byte length
            bufferMem[writeIdx++] = (byte) v;
        }
        return writeIdx;
    }

    /**
     * Sets in-memory variables capturing possible incoming CTAP options to their default values
     */
    private void defaultOptions() {
        tempBools[IDX_OPTION_UP] = true;
        tempBools[IDX_OPTION_UV] = false;
        tempBools[IDX_OPTION_RK] = false;
    }

    /**
     * Reads a CBOR "options" map from bufferMem. After call, in-memory booleans corresponding to
     * the passed options are set as dictated by the input
     *
     * @param apdu Request/response object
     * @param readIdx Read index into bufferMem
     * @param lc Length of incoming request, as sent by the platform
     *
     * @return New read index after consuming the options map object
     */
    private short processOptionsMap(APDU apdu, short readIdx, short lc) {
        if ((bufferMem[readIdx] & 0xF0) != 0xA0) { // map
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short numOptions = (short)(bufferMem[readIdx++] & 0x0F);
        if (readIdx > (short)(lc - 3)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        for (short j = 0; j < numOptions; j++) {
            if ((bufferMem[readIdx] & 0xF0) != 0x60) { // string
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            short optionStrLen = (short)(bufferMem[readIdx++] & 0x0F);
            if (optionStrLen != 2 || (bufferMem[readIdx] != 'u' && bufferMem[readIdx] != 'r')) {
                // unknown option; ignore it and its value
                readIdx += optionStrLen;
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
                continue;
            }

            if (bufferMem[readIdx] == 'r' && bufferMem[(short)(readIdx+1)] == 'k') {
                // rk option
                readIdx += 2;
                if (bufferMem[readIdx] == (byte) 0xF5) { // true
                    tempBools[IDX_OPTION_RK] = true;
                } else if (bufferMem[readIdx] == (byte) 0xF4) { // false
                    tempBools[IDX_OPTION_RK] = false;
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            } else {
                short pOrVPos = ++readIdx;

                if (bufferMem[pOrVPos] != 'p' && bufferMem[pOrVPos] != 'v') {
                    // unknown two-character option starting with 'u'...
                    readIdx++;
                    readIdx = consumeAnyEntity(apdu, readIdx, lc);
                    continue;
                }

                byte val = bufferMem[++readIdx];
                if (val == (byte) 0xF5) { // true
                    if (bufferMem[pOrVPos] == 'p') {
                        tempBools[IDX_OPTION_UP] = true;
                    } else {
                        tempBools[IDX_OPTION_UV] = true;
                    }
                } else if (val == (byte) 0xF4) { // false
                    if (bufferMem[pOrVPos] == 'p') {
                        tempBools[IDX_OPTION_UP] = false;
                    } else {
                        tempBools[IDX_OPTION_UV] = false;
                    }
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            }
            readIdx++;
        }

        return readIdx;
    }

    /**
     * After call, DH platform<->authenticator shared secret is available:
     * sharedSecretWrapper and sharedSecretUnwrapper may be used
     *
     * @param buf Buffer containing platform public key
     * @param xOff Index of the platform key's X coordinate in the given buffer
     * @param yOff Index of the platform key's Y coordinate in the given buffer
     */
    private void prepareSharedSecret(byte[] buf, short xOff, short yOff) {
        final short fullKeyLength = KEY_POINT_LENGTH * 2 + 1;

        short scratchOff = scratchAlloc(fullKeyLength);
        short scratchStartOff = scratchOff;

        // Pack the public key into scratch space so we can complete DH agreement...
        scratch[scratchOff++] = 0x04; // "Uncompressed" EC point format
        scratchOff = Util.arrayCopyNonAtomic(buf, xOff,
                scratch, scratchOff, KEY_POINT_LENGTH);
        scratchOff = Util.arrayCopyNonAtomic(buf, yOff,
                scratch, scratchOff, KEY_POINT_LENGTH);

        // DH-generate the shared secret... (overwriting the public key we just put in the buffer)
        short rawSecretLength = keyAgreement.generateSecret(
                scratch, scratchStartOff, fullKeyLength,
                scratch, scratchStartOff
        );
        // This was a "plain" DH so we need to sha256 the result to get the real secret
        short sharedSecretLength = sha256.doFinal(scratch, scratchStartOff, rawSecretLength,
                privateKeySpace, (short) 0);
        if (sharedSecretLength != privateKeySpace.length) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // Now, finally, the shared secret is ready!
        sharedSecretKey.setKey(privateKeySpace, (short) 0);
        sharedSecretWrapper.init(sharedSecretKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
        sharedSecretUnwrapper.init(sharedSecretKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);

        scratchRelease(fullKeyLength);
    }

    /**
     * Does the math for the FIDO2 hmac-secret extension. After call, the output
     * buffer contains a blob appropriate to send back to the platform as the value
     * produced by the hmac-secret extension.
     *
     * Note that this function overwrites privateScratch!
     *
     * @param apdu Request/response object
     * @param readIdx Index into bufferMem pointing to the start of the hmac-secret extension input CBOR
     *                map. Must contain the platform key agreement key...
     * @param lc Length of incoming request, as sent by the platform
     * @param outBuffer Buffer into which to pack the HMAC secret result
     * @param outOffset Write index into output buffer
     *
     * @return New read index into bufferMem after consuming HMAC-secret options
     */
    private short computeHMACSecret(APDU apdu, short readIdx, short lc, byte[] outBuffer, short outOffset) {
        if (bufferMem[readIdx++] != (byte) 0xA3) { // map, three entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx >= (short)(lc - (PUBLIC_KEY_DH_ALG_PREAMBLE.length + KEY_POINT_LENGTH * 2 + 7))) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (bufferMem[readIdx++] != 0x01) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readIdx = consumeKeyAgreement(apdu, readIdx);

        if (bufferMem[readIdx++] != 0x02) { // map key: saltEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x58) { // byte string: one byte length
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short saltLen = ub(bufferMem[readIdx++]);
        if (saltLen != 32 && saltLen != 64) { // Standard says one or two 32-byte salts
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
        }
        short saltIdx = readIdx;

        if (readIdx >= (short)(lc - saltLen - 2 - 16)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short scratchAllocAmt = 80;
        short scratchFOff = scratchAlloc((short) 32);
        short scratchSOff = scratchAlloc((short) 32);
        short scratchTOff = scratchAlloc((short) 16);
        short unwrapped = sharedSecretUnwrapper.doFinal(bufferMem, readIdx, saltLen,
                scratch, scratchFOff
        ); // NB: we either just wrote into scratchFOff, or both scratchFOff and scratchSOff, depending on saltLen
        if (unwrapped != saltLen) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }
        readIdx += saltLen;

        if (bufferMem[readIdx++] != 0x03) { // map key: saltAuth
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x50) { // byte string, 16 bytes long
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        sharedSecretKey.getKey(privateKeySpace, (short) 0);
        hmacSha256(privateKeySpace, (short) 0,
                bufferMem, saltIdx, saltLen,
                scratch, scratchTOff
        );

        if (Util.arrayCompare(scratch, scratchTOff,
                bufferMem, readIdx, (short) 16
        ) != 0) {
            // We must have gotten the crypto wrong somehow... (or the platform sent incorrect vals)
            // our computed HMAC didn't match the input
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }
        readIdx += 16;

        // If we're here, we've correctly validated that we have the right sharedSecret
        // (and the right salt index and length...)
        // It's time to do some hashing!

        // We will derive the HMAC secret key from the credential private key and an on-device key
        // ... by doing an HMAC-SHA256 of the credential private key using the HMAC-specific on-device key
        deriveHMACSecretFromPrivateKey(privateScratch, (short) 0,
                privateScratch, (short) 0);
        // ... and then use that as our HMAC secret! It's in privateScratch bytes 0-31.

        // HMAC the first salt
        hmacSha256(privateScratch, (short) 0,
                scratch, scratchFOff, (short) 32,
                scratch, scratchFOff);
        if (saltLen == 64) {
            // if there's a second salt, HMAC that too
            hmacSha256(privateScratch, (short) 0,
                    scratch, scratchSOff, (short) 32,
                    scratch, scratchSOff);
        }

        // encrypt the salted hashes using the shared secret, and that's our result
        short hmacSecretBytes = sharedSecretWrapper.doFinal(scratch, scratchFOff, saltLen,
                outBuffer, outOffset
        );
        if (hmacSecretBytes != saltLen) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        scratchRelease(scratchAllocAmt);

        return hmacSecretBytes;
    }

    /**
     * Derives the private key to be used for the hmac-secret extension for a particular credential
     * from that credential's private key. After call, the output buffer contains a 32-byte-long
     * private key which is not the same as the input one, but deterministically producible from it
     *
     * @param privKeyForDerivation Buffer containing credential private key bytes
     * @param privKeyOffset Offset of private key bytes in input buffer
     * @param output Buffer into which to write output
     * @param outputOffset Write index into output buffer
     */
    private void deriveHMACSecretFromPrivateKey(byte[] privKeyForDerivation, short privKeyOffset,
                                                byte[] output, short outputOffset) {
        hmacSha256(hmacWrapperBytes, (short) 0,
                privKeyForDerivation, privKeyOffset, (short) 32,
                output, outputOffset);
    }

    /**
     * Deciphers a credential ID block and compares its RP hash ID with a given value.
     * Before call, the symmetric secret must be initialized.
     * After call, the output buffer will contain: credPrivateKey || RPIDHash
     *
     * @param credentialBuffer Buffer containing the credential ID
     * @param credentialIndex Index of the credential ID block in the incoming buffer
     * @param credentialLen Length of the credential ID, as sent by the platform
     * @param rpIdBuf Buffer containing the RP ID hash
     * @param rpIdHashIdx Index of the RP ID hash within the given buffer
     * @param outputBuffer Buffer into which to store the decoded credential ID
     * @param outputOffset Offset into the output buffer for write
     *
     * @return true if the credential decrypts to match the given RP ID hash, false otherwise
     */
    private boolean checkCredential(byte[] credentialBuffer, short credentialIndex, short credentialLen,
                                    byte[] rpIdBuf, short rpIdHashIdx,
                                    byte[] outputBuffer, short outputOffset) {
        if (credentialLen != CREDENTIAL_ID_LEN) {
            // Someone's playing silly games...
            return false;
        }

        short numBytesUnwrapped = symmetricUnwrapper.doFinal(credentialBuffer, credentialIndex,
                credentialLen, outputBuffer, outputOffset);
        if (numBytesUnwrapped != CREDENTIAL_ID_LEN) {
            return false;
        }

        if (Util.arrayCompare(outputBuffer, (short) (outputOffset + 32), rpIdBuf, rpIdHashIdx, RP_HASH_LEN) == 0) {
            return true;
        }

        return false;
    }

    /**
     * Sends the request/response buffer to the platform as a response. If the response is too long
     * for the platform - based on whether the incoming request used extended-length APDUs - will
     * send the first chunk and set internal state to continue the response later.
     *
     * @param apdu Request/response object
     * @param outputLen Length of the output buffer, in bytes. Output always starts at index zero
     */
    private void doSendResponse(APDU apdu, short outputLen) {
        scratchRelease();

        final short bufferChunkSize = 256;

        if (outputLen < bufferChunkSize || apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA) {
            // If we're under one chunk or okay to use extended length APDUs, send in one go
            sendByteArray(apdu, bufferMem, outputLen);
        } else {
            // else, send one chunk and set state to continue response delivery later
            apdu.setOutgoing();
            apdu.setOutgoingLength(bufferChunkSize);
            Util.arrayCopyNonAtomic(bufferMem, (short) 0,
                    apdu.getBuffer(), (short) 0, bufferChunkSize);
            apdu.sendBytes((short) 0, bufferChunkSize);
            tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] = bufferChunkSize;
            tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] = (short)(outputLen - bufferChunkSize);
            if (tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] >= bufferChunkSize) {
                // at least ANOTHER full chunk remains
                throwException(ISO7816.SW_BYTES_REMAINING_00);
            } else {
                // exactly one more chunk remains
                throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING]));
            }
        }
    }

    /**
     * Gets a byte as a short representing its UNsigned value
     *
     * @param b Byte to convert
     *
     * @return Short integer, always positive, representing the byte as unsigned
     */
    private short ub(byte b) {
        return (short)(0xFF & b);
    }

    /**
     * Consumes and discards an arbitrary CBOR object. Is recursive, so relies on FIDO2 nesting depth standard to
     * avoid stack overflow in valid cases.
     *
     * @param apdu Request/response object
     * @param readIdx Current index into incoming request buffer
     * @param lc Length of request, as sent by the platform
     *
     * @return New index into incoming request buffer after consuming one CBOR object of any type
     */
    private short consumeAnyEntity(APDU apdu, short readIdx, short lc) {
        byte b = bufferMem[readIdx];
        short s = ub(b);

        if ((b >= 0 && b <= 0x17) || (b >= 0x20 && b <= 0x37) || b == (byte)0xF4 || b == (byte)0xF5) {
            return (short)(readIdx + 1);
        }
        if (b == 0x18 || b == 0x38) {
            return (short) (readIdx + 2);
        }
        if (b == 0x19 || b == 0x39) {
            return (short) (readIdx + 3);
        }
        if (b == 0x58 || b == 0x78) {
            return (short) (readIdx + 2 + bufferMem[(short)(readIdx+1)]);
        }
        if (b == 0x59 || b == 0x79) {
            short len = (short) (bufferMem[(short)(readIdx + 1)] << 8 + bufferMem[(short)(readIdx + 2)]);
            return (short) (readIdx + 2 + len);
        }
        if (b >= 0x40 && b <= 0x57) {
            return (short)(readIdx + 1 + b - 0x40);
        }
        if (b >= 0x60 && b <= 0x77) {
            return (short)(readIdx + 1 + b - 0x60);
        }
        if (b == (byte)0x98) {
            short l = ub(bufferMem[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
            }
            return readIdx;
        }
        if (b == (byte)0x99) {
            short l = (short)(bufferMem[(short)(readIdx + 1)] << 8 + bufferMem[(short)(readIdx + 2)]);
            if (l == Short.MAX_VALUE) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            readIdx += 2;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
            }
            return readIdx;
        }
        if (s > 0x80 && s <= 0x97) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0x80); i++) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
            }
            return readIdx;
        }
        if (s > 0xA0 && s <= 0xB7) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0xA0); i++) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0xB8) {
            short l = ub(bufferMem[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, readIdx, lc);
            }
            return readIdx;
        }

        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        return readIdx;
    }

    /**
     * Consumes a CBOR map and locates the element having string key "id". After call, temp variables
     * representing the index and length of the matched value are set, if a match was found. Values for the ID
     * element are allowed to be string or byte arrays. Before call those variables should be cleared, as there's
     * no way to determine if they are set as a result of the call other than comparing.
     *
     * @param apdu Request/response object
     * @param readIdx Current index into the request buffer
     * @param lc Length of the request buffer, as sent by the platform
     *
     * @return New index into the request buffer, after consuming one CBOR map element
     */
    private short consumeMapAndGetID(APDU apdu, short readIdx, short lc) {
        short mapDef = bufferMem[readIdx++];
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        short mapEntryCount = 0;
        if ((mapDef & 0xF0) == 0xA0) {
            mapEntryCount = (short) (mapDef & 0x0F);
        } else if ((mapDef & 0xF0) == 0xB0) {
            mapEntryCount = (short) ((mapDef & 0x0F) + 16);
        } else if (mapDef == (byte) 0xB8) {
            mapEntryCount = ub(bufferMem[readIdx++]);
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        for (short i = 0; i < mapEntryCount; i++) {
            short keyDef = bufferMem[readIdx++];
            short keyLen = 0;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            if (keyDef == 0x78) {
                keyLen = ub(bufferMem[readIdx++]);
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
            } else if (keyDef >= 0x61 && keyDef < 0x78) {
                keyLen = (short)(keyDef - 0x60);
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            boolean isId = (keyLen == 2 && bufferMem[readIdx] == 'i' && bufferMem[(short)(readIdx+1)] == 'd');
            readIdx += keyLen;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            short valDef = bufferMem[readIdx++];
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            if (isId) {
                tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = readIdx;
            }

            short valLen = 0;
            if (valDef == 0x78 || valDef == 0x58) {
                valLen = ub(bufferMem[readIdx++]);
                if (isId) {
                    tempShorts[IDX_TEMP_BUF_IDX_STORAGE]++;
                }
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
            } else if (valDef >= 0x61 && valDef < 0x78) {
                valLen = (short) (valDef - 0x60);
            } else if (valDef >= 0x41 && valDef < 0x58) {
                valLen = (short) (valDef - 0x40);
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            if (isId) {
                tempShorts[IDX_TEMP_BUF_IDX_LEN] = valLen;
            }

            readIdx += valLen;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
        }

        if (tempShorts[IDX_TEMP_BUF_IDX_STORAGE] == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        return readIdx;
    }

    /**
     * Called by the platform when a new APDU comes in - entry point for the applet, really
     *
     * @param apdu Request/response object
     * @throws ISOException If an error occurs outside cases representable by CTAP2 error responses
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        initKeyAgreementKeyIfNecessary();

        if (selectingApplet()) {
            // For U2F compatibility, the CTAP2 standard requires that we respond to select() as if we were a U2F
            // authenticator, and then let the platform figure out we're really CTAP2 by making a getAuthenticatorInfo
            // API request afterwards
            // sendByteArray(apdu, U2F_V2_RESPONSE);

            // ... but we DON'T implement U2F, so we can send the CTAP2-only response type
            sendByteArray(apdu, FIDO_2_RESPONSE);

            return;
        }

        byte[] apduBytes = apdu.getBuffer();

        if (apduBytes[ISO7816.OFFSET_CLA] == 0x00 && apduBytes[ISO7816.OFFSET_INS] == (byte) 0xC0) {
            if (tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] == 0 || tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] == 0) {
                throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            short writeSize = 256 <= tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] ? 256 : tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING];
            apdu.setOutgoing();
            apdu.setOutgoingLength(writeSize);
            Util.arrayCopyNonAtomic(bufferMem, tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET],
                    apdu.getBuffer(), (short) 0, writeSize);
            apdu.sendBytes((short) 0, writeSize);
            tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] += writeSize;
            tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] -= writeSize;
            if (tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] >= 256) {
                throwException(ISO7816.SW_BYTES_REMAINING_00);
            } else if (tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] > 0) {
                throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING]));
            }
            tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] = 0;
            return;
        } else {
            tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] = 0;
            tempShorts[IDX_CONTINUATION_OUTGOING_REMAINING] = 0;
        }

        if (apdu.isCommandChainingCLA()) {
            short amtRead = apdu.setIncomingAndReceive();

            short lc = apdu.getIncomingLength();
            if (lc == 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            fullyReadReq(apdu, apduBytes, lc, amtRead);

            tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] += lc;
            if (tempShorts[IDX_STORED_COMMAND_BYTE] == 0x00) {
                tempShorts[IDX_STORED_COMMAND_BYTE] = ub(apduBytes[apdu.getOffsetCdata()]);
            }

            return;
        }

        if (apduBytes[ISO7816.OFFSET_CLA] != (byte)0x80) {
            throwException(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (apduBytes[ISO7816.OFFSET_INS] != 0x10) {
            throwException(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        if ((apduBytes[ISO7816.OFFSET_P1] != 0x00 && apduBytes[ISO7816.OFFSET_P1] != (byte) 0x80) || apduBytes[ISO7816.OFFSET_P2] != 0x00) {
            throwException(ISO7816.SW_INCORRECT_P1P2);
        }

        short amtRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();

        if (amtRead == 0) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        short incomingOffset = 1;
        short lcEffective = (short)(lc + 1);
        byte cmdByte = apduBytes[apdu.getOffsetCdata()];
        if (tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] > 0) {
            cmdByte = bufferMem[0];
            lcEffective += tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET];
            tempShorts[IDX_STORED_COMMAND_BYTE] = 0x00;
        }

        if (cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT
            && cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT_PREVIEW) {
            tempShorts[IDX_CRED_ITERATION_POINTER] = 0;
            tempShorts[IDX_RP_ITERATION_POINTER] = 0;
        }

        switch (cmdByte) {
            case FIDOConstants.CMD_MAKE_CREDENTIAL:
                fullyReadReq(apdu, apduBytes, lc, amtRead);

                makeCredential(apdu, lcEffective, incomingOffset);
                break;
            case FIDOConstants.CMD_GET_INFO:
                sendAuthInfo(apdu);
                break;
            case FIDOConstants.CMD_GET_ASSERTION:
                fullyReadReq(apdu, apduBytes, lc, amtRead);

                getAssertion(apdu, lcEffective, incomingOffset);
                break;
            case FIDOConstants.CMD_GET_NEXT_ASSERTION:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
                break;
            case FIDOConstants.CMD_CLIENT_PIN:
                fullyReadReq(apdu, apduBytes, lc, amtRead);

                clientPINSubcommand(apdu, incomingOffset, lcEffective);
                break;
            case FIDOConstants.CMD_RESET:
                authenticatorReset(apdu);
                break;
            case FIDOConstants.CMD_CREDENTIAL_MANAGEMENT: // intentional fallthrough, for backwards compat
            case FIDOConstants.CMD_CREDENTIAL_MANAGEMENT_PREVIEW:
                fullyReadReq(apdu, apduBytes, lc, amtRead);

                credManagementSubcommand(apdu, lcEffective, incomingOffset);
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_COMMAND);
                break;
        }

        tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
    }

    /**
     * Handler to consume and dispatch subcommands for the credential management optional feature
     *
     * @param apdu Request/response object
     * @param lc Length of incoming request, as sent by the platform
     * @param readIdx Read index into bufferMem
     */
    private void credManagementSubcommand(APDU apdu, short lc, short readIdx) {
        if (!pinSet) {
            // All credential management commands require and validate a PIN
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if ((bufferMem[readIdx] & 0xF0) != 0xA0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short numOptions = (short) (bufferMem[readIdx++] & 0x0F);

        if (bufferMem[readIdx++] != 0x01) { // map key: subCommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        short subcommandIdx = readIdx;
        short subCommandNumber = ub(bufferMem[readIdx++]);
        if (subCommandNumber > 23) {
            // This will likely never be legal...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short subCommandParamsIdx = -1;
        short subCommandParamsLen = 0;
        if (bufferMem[readIdx] == 0x02) { // map key: subCommandParams
            subCommandParamsIdx = ++readIdx;
            readIdx = consumeAnyEntity(apdu, readIdx, lc);
            subCommandParamsLen = (short)(readIdx - subCommandParamsIdx);
        }

        if (subCommandNumber != FIDOConstants.CRED_MGMT_ENUMERATE_RPS_NEXT &&
            subCommandNumber != FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_NEXT) {
            // Don't ask me why these commands don't need the PIN token...
            if (bufferMem[readIdx++] != 0x03) { // map key: pinUvAuthProtocol
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (bufferMem[readIdx++] != 0x01) { // protocol one
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            }

            if (bufferMem[readIdx++] != 0x04) { // map key: pinUvAuthParam
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (bufferMem[readIdx++] != 0x50) { // byte array, 16 bytes long
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            // Check PIN token
            short scratchAmt = (short)(1 + subCommandParamsLen);
            short scratchOff = scratchAlloc(scratchAmt);
            scratch[scratchOff] = bufferMem[subcommandIdx];
            if (subCommandParamsLen > 80) {
                // 64 bytes for a credential ID for deleteCred plus some CBOR overhead
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            if (subCommandParamsLen > 0) {
                Util.arrayCopyNonAtomic(bufferMem, subCommandParamsIdx,
                        scratch, (short)(scratchOff + 1), subCommandParamsLen);
            }
            checkPinTokenProtocolOne(apdu, scratch, (short) 0, scratchAmt,
                    bufferMem, readIdx);
            scratchRelease(scratchAmt);
        }

        switch (subCommandNumber) {
            case FIDOConstants.CRED_MGMT_GET_CREDS_META:
                handleCredentialManagementGetCredsMetadata(apdu);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_RPS_BEGIN:
                handleEnumerateRPs(apdu, (short) 0);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_RPS_NEXT:
                short rpPtr = tempShorts[IDX_RP_ITERATION_POINTER];
                if (rpPtr == 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                }
                handleEnumerateRPs(apdu, rpPtr);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_NEXT:
                short credPtr = tempShorts[IDX_CRED_ITERATION_POINTER];
                if (credPtr == 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                }
                handleEnumerateCreds(apdu, (short) -1, credPtr, lc);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_BEGIN:
                handleEnumerateCreds(apdu, subCommandParamsIdx, (short) 0, lc);
                break;
            case FIDOConstants.CRED_MGMT_DELETE_CRED:
                handleDeleteCred(apdu, subCommandParamsIdx, lc);
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                break;
        }
    }

    /**
     * Deletes a resident key by its credential ID blob, and updates bookkeeping state to match
     *
     * @param apdu Request/response object
     * @param readOffset Read index into bufferMem
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleDeleteCred(APDU apdu, short readOffset, short lc) {
        tempShorts[IDX_CRED_ITERATION_POINTER] = 0;
        tempShorts[IDX_RP_ITERATION_POINTER] = 0;

        if (bufferMem[readOffset++] != (byte) 0xA1) { // map with one entry
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (bufferMem[readOffset++] != 0x02) { // map key: credentialId
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        tempShorts[IDX_TEMP_BUF_IDX_STORAGE] = 0;
        readOffset = consumeMapAndGetID(apdu, readOffset, lc);
        short credIdIdx = tempShorts[IDX_TEMP_BUF_IDX_STORAGE];
        short credIdLen = tempShorts[IDX_TEMP_BUF_IDX_LEN];

        if (credIdLen != CREDENTIAL_ID_LEN) {
            // We're not gonna have credentials of random lengths on here...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        for (short i = 0; i < NUM_RESIDENT_KEY_SLOTS; i++) {
            if (!residentKeyValidity[i]) {
                continue;
            }

            // Compare still encrypted, which is fine
            if (Util.arrayCompare(residentKeyData, (short)(i * CREDENTIAL_ID_LEN),
                    bufferMem, credIdIdx, CREDENTIAL_ID_LEN) == 0) {
                // Found a match!

                if (residentKeyUniqueRP[i]) {
                    // Due to how we manage RP validity, we need to find ANOTHER RK with the same RP,
                    // to set residentKeyUniqueRP on it and thus "promote" it to being the representative
                    // of the RP for iteration purposes
                    short rpHavingSameRP = -1;

                    short unpackedCredIdx = scratchAlloc(CREDENTIAL_ID_LEN);
                    short unpackedSecondCredIdx = scratchAlloc(CREDENTIAL_ID_LEN);
                    symmetricUnwrapper.doFinal(
                            bufferMem, credIdIdx, CREDENTIAL_ID_LEN,
                            scratch, unpackedCredIdx
                    );
                    short rpIdHashIdx = (short)(unpackedCredIdx + 32);

                    for (short otherRKIdx = 0; otherRKIdx < NUM_RESIDENT_KEY_SLOTS; otherRKIdx++) {
                        if (otherRKIdx == i) {
                            // we want ANOTHER RK, not this one...
                            continue;
                        }
                        if (!residentKeyValidity[i]) {
                            // deleted keys need not apply
                            continue;
                        }
                        if (checkCredential(residentKeyData, (short)(otherRKIdx * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                                scratch, rpIdHashIdx,
                                scratch, unpackedSecondCredIdx)) {
                            // match. this is our promotion candidate!
                            rpHavingSameRP = otherRKIdx;
                            break;
                        }
                    }

                    JCSystem.beginTransaction();
                    if (rpHavingSameRP == -1) {
                        // We couldn't find anybody else that shared our RP, which means deleting us
                        // also lowered the total RP count by one
                        numResidentRPs--;
                    } else {
                        residentKeyUniqueRP[rpHavingSameRP] = true;
                    }
                    residentKeyValidity[i] = false;
                    numResidentCredentials--;
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.beginTransaction();
                    residentKeyValidity[i] = false;
                    numResidentCredentials--;
                    JCSystem.commitTransaction();
                }

                bufferMem[0] = FIDOConstants.CTAP2_OK;
                doSendResponse(apdu, (short) 1);
                return;
            }
        }

        // If we got here, we didn't find a matching credential
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
    }

    /**
     * Enumerates creds
     *
     * @param apdu Request/response object
     * @param bufferIdx Read index into bufferMem
     * @param startCredIdx Offset of the first credential to consider, in the resident key slots.
     *                     If zero, we're starting a new iteration
     * @param lc Length of the incoming request, as sent by the platform
     */
    private void handleEnumerateCreds(APDU apdu, short bufferIdx, short startCredIdx, short lc) {
        tempShorts[IDX_CRED_ITERATION_POINTER] = 0;

        if (startCredIdx > NUM_RESIDENT_KEY_SLOTS) { // intentional > instead of >=
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        byte[] rpIdHashBuf;
        short rpIdHashIdx;
        if (startCredIdx == 0) {
            // Iteration start: read RP ID hash from request buffer
            if (bufferMem[bufferIdx++] != (byte) 0xA1) { // map, one entry
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (bufferMem[bufferIdx++] != 0x01) { // map key: rpIdHash
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (bufferMem[bufferIdx++] != 0x58 || bufferMem[bufferIdx++] != RP_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            rpIdHashBuf = bufferMem;
            rpIdHashIdx = bufferIdx;

            if ((short)(bufferIdx + RP_HASH_LEN) >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
        } else {
            // Continuing iteration, we get the RP ID hash from the previous credential
            rpIdHashBuf = scratch;
            short allocBuf = scratchAlloc(CREDENTIAL_ID_LEN);
            symmetricUnwrapper.doFinal(
                    residentKeyData, (short) ((startCredIdx - 1) * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                    rpIdHashBuf, allocBuf
            );
            rpIdHashIdx = (short)(allocBuf + 32); // RP ID hash is the second half of the unwrapped credential
        }

        short rkIndex;
        for (rkIndex = startCredIdx; rkIndex < NUM_RESIDENT_KEY_SLOTS; rkIndex++) {
            if (!residentKeyValidity[rkIndex]) {
                continue;
            }

            if (checkCredential(
                    residentKeyData, (short) (rkIndex * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                    rpIdHashBuf, rpIdHashIdx,
                    privateScratch, (short) 0)) {
                // Cred is for this RP ID, yay.

                byte matchingCount = 1; // remember to count THIS cred as a match
                if (startCredIdx == 0) {
                    short scratchOffsetForCredComparison = scratchAlloc(CREDENTIAL_ID_LEN);

                    // Unfortunately, we need to scan forward through all remaining credentials
                    // we're not storing a list of which creds share an RP, so this is the only way to get
                    // the count associated with this RP...
                    for (short otherCredIdx = (short) (rkIndex + 1); otherCredIdx < NUM_RESIDENT_KEY_SLOTS; otherCredIdx++) {
                        if (!residentKeyValidity[otherCredIdx]) {
                            continue;
                        }

                        if (checkCredential(
                                residentKeyData, (short)(otherCredIdx * CREDENTIAL_ID_LEN), CREDENTIAL_ID_LEN,
                                rpIdHashBuf, rpIdHashIdx,
                                scratch, scratchOffsetForCredComparison
                        )) {
                            matchingCount++;
                        }
                    }

                    scratchRelease(CREDENTIAL_ID_LEN);
                }
                tempShorts[IDX_CRED_ITERATION_POINTER] = (short)(rkIndex + 1); // resume iteration from beyond this one

                short writeOffset = 0;

                bufferMem[writeOffset++] = FIDOConstants.CTAP2_OK;
                bufferMem[writeOffset++] = startCredIdx == 0 ? (byte) 0xA5 : (byte) 0xA4; // map, four or five entries
                bufferMem[writeOffset++] = 0x06; // map key: pubKeyCredentialsUserEntry
                writeOffset = Util.arrayCopyNonAtomic(SINGLE_ID_MAP_PREAMBLE, (short) 0,
                        bufferMem, writeOffset, (short) SINGLE_ID_MAP_PREAMBLE.length);
                short userIdLength = ub(residentKeyUserIdLengths[rkIndex]);
                writeOffset = encodeIntLen(writeOffset, userIdLength, true);

                short userIdOff = scratchAlloc(MAX_USER_ID_LENGTH);
                symmetricUnwrapper.doFinal(residentKeyUserIds, (short)(MAX_USER_ID_LENGTH * rkIndex), MAX_USER_ID_LENGTH,
                        scratch, userIdOff);
                writeOffset = Util.arrayCopyNonAtomic(scratch, userIdOff,
                        bufferMem, writeOffset, userIdLength);
                scratchRelease(MAX_USER_ID_LENGTH);

                bufferMem[writeOffset++] = 0x07; // map key: credentialId
                writeOffset = Util.arrayCopyNonAtomic(SINGLE_ID_MAP_PREAMBLE, (short) 0,
                        bufferMem, writeOffset, (short) SINGLE_ID_MAP_PREAMBLE.length);
                writeOffset = encodeIntLen(writeOffset, CREDENTIAL_ID_LEN, true);
                writeOffset = Util.arrayCopyNonAtomic(residentKeyData, (short)(CREDENTIAL_ID_LEN * rkIndex),
                        bufferMem, writeOffset, CREDENTIAL_ID_LEN);

                bufferMem[writeOffset++] = 0x08; // map key: publicKey
                writeOffset = Util.arrayCopyNonAtomic(PUBLIC_KEY_ALG_PREAMBLE, (short) 0,
                        bufferMem, writeOffset, (short) PUBLIC_KEY_ALG_PREAMBLE.length);
                short pubKeyOff = scratchAlloc((short)(KEY_POINT_LENGTH * 2));
                symmetricUnwrapper.doFinal(residentKeyPublicKeys, (short)(rkIndex * KEY_POINT_LENGTH * 2), (short)(KEY_POINT_LENGTH * 2),
                        scratch, pubKeyOff);
                writeOffset = writePubKey(writeOffset, scratch, pubKeyOff);
                scratchRelease((short)(KEY_POINT_LENGTH * 2));

                if (startCredIdx == 0) {
                    bufferMem[writeOffset++] = 0x09; // map key: totalCredentials
                    writeOffset = encodeInt(writeOffset, matchingCount);
                }

                bufferMem[writeOffset++] = 0x0A; // map key: credProtect
                bufferMem[writeOffset++] = 0x03; // cred protect level 3

                doSendResponse(apdu, writeOffset);
                return;
            }
        }

        // If we fall through to here, we didn't find a cred
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
    }

    /**
     * Handles enumerating stored RPs on the authenticator
     *
     * @param apdu Request/response offset
     * @param startOffset The index of the next RK which has a "unique" RP
     */
    private void handleEnumerateRPs(APDU apdu, short startOffset) {
        // if anything goes wrong, iteration will need to be restarted
        tempShorts[IDX_RP_ITERATION_POINTER] = 0;

        short rkIndex;
        for (rkIndex = startOffset; rkIndex < NUM_RESIDENT_KEY_SLOTS; rkIndex++) {
            // if a credential is not for a *unique* RP, ignore it - we're enumerating RPs here!
            if (residentKeyValidity[rkIndex] && residentKeyUniqueRP[rkIndex]) {
                break;
            }
        }

        if (rkIndex >= NUM_RESIDENT_KEY_SLOTS) {
            // Iterated too far, or called with no stored creds...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        boolean isContinuation = startOffset > 0;

        short writeOffset = 0;

        bufferMem[writeOffset++] = FIDOConstants.CTAP2_OK;
        // Unwrap the given RK and its ID so we can return its decrypted hash, etc
        short numBytesUnwrapped = symmetricUnwrapper.doFinal(residentKeyData, (short) (CREDENTIAL_ID_LEN * rkIndex), CREDENTIAL_ID_LEN,
                privateScratch, (short) 0);
        if (numBytesUnwrapped != CREDENTIAL_ID_LEN) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        short rkReturnOffset = scratchAlloc(MAX_RESIDENT_RP_ID_LENGTH);
        numBytesUnwrapped = symmetricUnwrapper.doFinal(residentKeyRPIds, (short) (MAX_RESIDENT_RP_ID_LENGTH * rkIndex), MAX_RESIDENT_RP_ID_LENGTH,
                scratch, rkReturnOffset);
        if (numBytesUnwrapped != MAX_RESIDENT_RP_ID_LENGTH) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        tempShorts[IDX_RP_ITERATION_POINTER] = (short)(rkIndex + 1);

        bufferMem[writeOffset++] = isContinuation ? (byte) 0xA2 : (byte) 0xA3; // map with two or three keys
        bufferMem[writeOffset++] = 0x03; // map key: rp
        writeOffset = Util.arrayCopyNonAtomic(SINGLE_ID_MAP_PREAMBLE, (short) 0,
                bufferMem, writeOffset, (short) SINGLE_ID_MAP_PREAMBLE.length);
        byte rpIdLength = residentKeyRPIdLengths[rkIndex];
        writeOffset = encodeIntLen(writeOffset, rpIdLength, false);
        writeOffset = Util.arrayCopyNonAtomic(scratch, rkReturnOffset,
                bufferMem, writeOffset, rpIdLength);
        bufferMem[writeOffset++] = 0x04; // map key: rpIdHash
        bufferMem[writeOffset++] = 0x58; // byte array with one-byte length
        bufferMem[writeOffset++] = RP_HASH_LEN;
        writeOffset = Util.arrayCopyNonAtomic(privateScratch, (short) 32,
                bufferMem, writeOffset, RP_HASH_LEN);

        if (!isContinuation) {
            bufferMem[writeOffset++] = 0x05; // map key: totalRPs
            if (numResidentRPs >= 24) {
                bufferMem[writeOffset++] = 0x18; // one-byte integer
            }
            bufferMem[writeOffset++] = numResidentRPs;
        }

        doSendResponse(apdu, writeOffset);
    }

    /**
     * Processes the CTAP2.1 credential management getCredsMetaData command
     *
     * @param apdu Request/response object
     */
    private void handleCredentialManagementGetCredsMetadata(APDU apdu) {
        short writeOffset = 0;

        bufferMem[writeOffset++] = FIDOConstants.CTAP2_OK;
        bufferMem[writeOffset++] = (byte) 0xA2; // map: two items
        bufferMem[writeOffset++] = 0x01; // map key: existingResidentCredentialsCount
        writeOffset = encodeInt(writeOffset, numResidentCredentials);
        bufferMem[writeOffset++] = 0x02; // map key: maxPossibleRemainingCredentialsCount
        short remainingCredentials = (short)(NUM_RESIDENT_KEY_SLOTS - numResidentCredentials);
        writeOffset = encodeInt(writeOffset, (byte) remainingCredentials);

        doSendResponse(apdu, writeOffset);
    }

    /**
     * Packs a low-valued integer as a CBOR value into bufferMem
     *
     * @param writeOffset Write offset into bufferMem
     * @param v Value to pack
     *
     * @return New write offset into bufferMem
     */
    private short encodeInt(short writeOffset, byte v) {
        if (v < 24) {
            bufferMem[writeOffset++] = v;
        } else {
            bufferMem[writeOffset++] = 0x18; // Integer stored in one byte
            bufferMem[writeOffset++] = v;
        }
        return writeOffset;
    }

    /**
     * Reset authenticator to factory fresh state
     *
     * @param apdu Request/response object
     */
    private void authenticatorReset(APDU apdu) {
        JCSystem.beginTransaction();

        boolean ok = false;
        try {
            random.generateData(hmacWrapperBytes, (short) 0, (short) hmacWrapperBytes.length);

            for (short i = 0; i < NUM_RESIDENT_KEY_SLOTS; i++) {
                residentKeyValidity[i] = false;
            }
            numResidentCredentials = 0;
            numResidentRPs = 0;

            pinSet = false;
            pinRetryCounter = MAX_PIN_RETRIES;

            random.generateData(pinKDFSalt, (short) 0, (short) pinKDFSalt.length);
            random.generateData(wrappingIV, (short) 0, (short) wrappingIV.length);

            resetWrappingKey();

            for (short i = 0; i < counter.length; i++) {
                counter[i] = 0;
            }

            for (short s = 0; s < tempShorts.length; s++) {
                tempShorts[s] = 0;
            }
            for (short s = 0; s < tempBools.length; s++) {
                tempBools[s] = false;
            }

            forceInitKeyAgreementKey();

            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
                sendErrorByte(apdu, FIDOConstants.CTAP2_OK);
            } else {
                JCSystem.abortTransaction();
                throwException(ISO7816.SW_UNKNOWN);
            }
        }
    }

    /**
     * Resets the "wrapping key" to a random value. THIS INVALIDATES ALL ISSUED CREDENTIALS.
     *
     * After call, symmetric crypto is available with the new (random) key.
     */
    private void resetWrappingKey() {
        random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
        wrappingKey.setKey(wrappingKeySpace, (short) 0);
        random.generateData(wrappingKeyValidation, (short) 0, (short) 32);

        // Put the HMAC-SHA256 of the first half of wrappingKeyValidation into the second half
        // We'll use this validate we have the correct wrapping key
        hmacSha256(wrappingKeySpace, (short) 0,
                wrappingKeyValidation, (short) 0, (short) 32,
                wrappingKeyValidation, (short) 32);

        initSymmetricCrypto();
    }

    /**
     * Replies to the FIDO2 authenticator info command
     *
     * @param apdu Request/response object
     */
    private void sendAuthInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short offset = 0;

        offset = Util.arrayCopyNonAtomic(AUTH_INFO_RESPONSE, (short) 0,
                buffer, offset, (short) AUTH_INFO_RESPONSE.length);

        if (pinSet) {
            buffer[offset++] = (byte) 0xF5; // true
        } else {
            buffer[offset++] = (byte) 0xF4; // false
        }

        buffer[offset++] = 0x06; // map key: pinProtocols
        buffer[offset++] = (byte) 0x81; // array: one item
        buffer[offset++] = 0x01; // pin protocol version 1

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    /**
     * Aborts processing and sends a particular status code to the platform.
     * Also releases any scratch memory and resets APDU chain handling state
     *
     * @param swCode Two-byte status code - may be SW_NO_ERROR if desired
     */
    private void throwException(short swCode) {
        tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
        tempShorts[IDX_CRED_ITERATION_POINTER] = 0;
        tempShorts[IDX_RP_ITERATION_POINTER] = 0;
        scratchRelease();

        ISOException.throwIt(swCode);
    }

    /**
     * Dispatches a FIDO2 clientPin subcommand
     *
     * @param apdu    Request/response object
     * @param readIdx Read index into bufferMem
     * @param lc      Length of incoming request, as sent by the platform
     */
    private void clientPINSubcommand(APDU apdu, short readIdx, short lc) {
        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if ((bufferMem[readIdx] & 0xF0) != 0xA0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short numOptions = (short) (bufferMem[readIdx++] & 0x0F);
        if (numOptions < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= (short)(lc - 4)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (bufferMem[readIdx++] != 0x01) { // map key: pinProtocol
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x01) { // pin protocol version 1
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        if (bufferMem[readIdx++] != 0x02) { // map key: subCommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        byte opType = bufferMem[readIdx++];

        switch (opType) {
            case FIDOConstants.CLIENT_PIN_GET_KEY_AGREEMENT:
                handleClientPinGetAgreement(apdu);
                return;
            case FIDOConstants.CLIENT_PIN_GET_RETRIES:
                handleClientPinGetRetries(apdu);
                return;
            case FIDOConstants.CLIENT_PIN_SET_PIN:
                handleClientPinInitialSet(apdu, readIdx, lc);
                return;
            case FIDOConstants.CLIENT_PIN_CHANGE_PIN:
                handleClientPinChange(apdu, readIdx, lc);
                return;
            case FIDOConstants.CLIENT_PIN_GET_PIN_TOKEN:
                handleClientPinGetToken(apdu, readIdx, lc);
                return;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                break;
        }
    }

    /**
     * Processes the CTAP2 clientPin change subcommand
     *
     * @param apdu Request/response object
     * @param readIdx Read index into request buffer
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleClientPinChange(APDU apdu, short readIdx, short lc) {
        if (!pinSet) {
            // need to have a PIN to change a PIN...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        short scratchOff = scratchAlloc((short) (PIN_PAD_LENGTH + 16)); // 16 bytes for PIN partial hash

        readIdx = handlePinSetPreamble(apdu, readIdx, lc, scratch, scratchOff, true);

        short wrappedPinLocation = readIdx;
        readIdx += PIN_PAD_LENGTH;

        if (bufferMem[readIdx++] != 0x06) { // pinHashEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x50) { // byte string: 16 bytes long
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx > (short)(lc - 16)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        // Decrypt the sent PIN hash using the shared secret
        short pinUnwrapped = sharedSecretUnwrapper.doFinal(bufferMem, readIdx, (short) 16,
                scratch, scratchOff);
        if (pinUnwrapped != 16) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        // Use pinHash, now decrypted, to unlock the symmetric wrapping key (or fail if the PIN is wrong...)
        testAndReadyPIN(apdu, scratch, scratchOff);

        // Decrypt the real PIN
        short unwrapped = sharedSecretUnwrapper.doFinal(bufferMem, wrappedPinLocation, (short) 64,
                scratch, scratchOff);
        if (unwrapped != PIN_PAD_LENGTH) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        short realPinLength = 0;
        for (; realPinLength < PIN_PAD_LENGTH; realPinLength++) {
            if (scratch[(short)(scratchOff + realPinLength)] == 0x00) {
                break;
            }
        }
        if (realPinLength < 4) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        rawSetPIN(apdu, scratch, scratchOff, realPinLength);

        bufferMem[0] = FIDOConstants.CTAP2_OK; // no data in the response to this command, just an OK status
        doSendResponse(apdu, (short) 1);
    }

    /**
     * Checks incoming pinHash and returns a pinToken to the platform for use in future commands
     * (until the next reset, of course...)
     *
     * @param apdu Request/response object
     * @param readIdx Read index into request buffer
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleClientPinGetToken(APDU apdu, short readIdx, short lc) {
        if (!pinSet) {
            // duh
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        if (bufferMem[readIdx++] != 0x03) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readIdx = consumeKeyAgreement(apdu, readIdx);

        if (bufferMem[readIdx++] != 0x06) { // map key: pinHashEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x50) { // byte string: 16 bytes long
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx > (short)(lc - 16)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short scratchAmt = 16;
        short scratchOff = scratchAlloc(scratchAmt);

        // Decrypt the 16 bytes of the PIN verification first
        short unwrapped = sharedSecretUnwrapper.doFinal(bufferMem, readIdx, (short) 16,
                scratch, scratchOff);
        if (unwrapped != 16) {
            throwException(ISO7816.SW_UNKNOWN);
        }

        testAndReadyPIN(apdu, scratch, scratchOff);

        scratchRelease(scratchAmt);

        // Output below here

        short writeOffset = 0;

        bufferMem[writeOffset++] = FIDOConstants.CTAP2_OK;
        bufferMem[writeOffset++] = (byte) 0xA1; // map: one item
        bufferMem[writeOffset++] = 0x02; // map key: pinToken
        bufferMem[writeOffset++] = 0x50; // byte string, sixteen bytes long

        writeOffset += sharedSecretWrapper.doFinal(pinToken, (short) 0, (short) pinToken.length,
                bufferMem, writeOffset);

        doSendResponse(apdu, writeOffset);
    }

    /**
     * Checks the SHA-256 hash of a PIN for correctness, and if it is correct, readies the authenticator unwrapping
     * key for use. After a successful call, symmetricWrapper and symmetricUnwrapper may be used.
     *
     * @param apdu Request/response object
     * @param buf Buffer potentially containing the first 16 bytes of the SHA-256 hash of the PIN
     * @param off Offset of the putative PIN hash within the given buffer
     */
    private void testAndReadyPIN(APDU apdu, byte[] buf, short off) {
        if (pinRetryCounter == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_BLOCKED);
        }

        if (tempShorts[IDX_PIN_TRIES_SINCE_RESET] == PIN_TRIES_PER_RESET) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_BLOCKED);
        }

        // Use PBKDF on the hash to derive a potential PIN key
        PBKDF2(buf, off, privateKeySpace, (short) 0);

        pinWrapKey.setKey(privateKeySpace, (short) 0);
        pinUnwrapper.init(pinWrapKey, Cipher.MODE_DECRYPT, wrappingIV, (short) 0, (short) wrappingIV.length);

        pinUnwrapper.doFinal(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length,
                privateKeySpace, (short) 0);

        short scratchOff = scratchAlloc((short) 32);

        // Compute HMAC-SHA256 of first 32 bytes of wrappingKeyValidation
        hmacSha256(privateKeySpace, (short) 0,
                   wrappingKeyValidation, (short) 0, (short) 32,
                   scratch, scratchOff);

        pinRetryCounter--; // decrement retry counter *before* checking if it's correct:
        // this will be reset to max if it is correct, and otherwise it's theoretically possible to
        // remove power from the authenticator between it determining correctness and decrementing the
        // counter. So we'll accept the risk that a good PIN still results in the counter going down
        // in the event of a strange failure.

        // ... and check that the result equals the second 32 bytes. If it does, we have the correct key.
        if (Util.arrayCompare(wrappingKeyValidation, (short) 32,
                scratch, scratchOff, (short) 32) == 0) {
            // Good PIN!
            pinRetryCounter = MAX_PIN_RETRIES;
            tempBools[IDX_RESET_PIN_PROVIDED] = true;
            wrappingKey.setKey(privateKeySpace, (short) 0);
            initSymmetricCrypto(); // Need to re-key the wrapper since we messed it up above
            tempShorts[IDX_PIN_TRIES_SINCE_RESET] = 0;
            scratchRelease((short) 32);
            return;
        }

        // BAD PIN
        tempShorts[IDX_PIN_TRIES_SINCE_RESET]++;
        forceInitKeyAgreementKey();
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
    }

    /**
     * Performs heavy lifting for setting new PINs and changing existing ones. After a successful call,
     * the PIN is not necessarily correct, but the platform-authenticator shared secret is consistent with it.
     *
     * @param apdu Request/response object
     * @param readIdx Starting index in request/response buffer of the keyAgreement (3rd) CTAP2 CBOR argument
     * @param lc Length of the incoming request, as declared by the platform
     * @param outBuf Buffer for result and scratch: minimum PIN_PAD_LENGTH+16 bytes allocated
     * @param outOffset Offset into output buffer. Again, must be at least PIN_PAD_LENGTH+16 bytes from the end of the buffer
     * @param expectPinHashEnc If true, expect that pinAuth matches hash(newPinEnc || pinHashEnc). In other words,
     *                         that an existing PIN was provided and this is a change-PIN operation
     *
     * @return Index into request/response buffer of the encrypted new PIN
     */
    private short handlePinSetPreamble(APDU apdu, short readIdx, short lc, byte[] outBuf, short outOffset,
                                       boolean expectPinHashEnc) {
        if (bufferMem[readIdx++] != 0x03) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readIdx = consumeKeyAgreement(apdu, readIdx);

        if (bufferMem[readIdx++] != 0x04) { // map key: pinAuth
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (bufferMem[readIdx++] != 0x50) { // byte string: 16 bytes long
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short pinAuthIdx = readIdx;
        readIdx += 16;

        if (bufferMem[readIdx++] != 0x05) { // map key: newPinEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short bLen = 0;
        byte pstrType = bufferMem[readIdx++];
        if (pstrType == 0x58) { // byte string, one-byte length
            bLen = ub(bufferMem[readIdx++]);
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        if (bLen != PIN_PAD_LENGTH) { // standard-mandated minimum pad for PINs
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
        }

        // Verify pinAuth before we proceed
        sharedSecretKey.getKey(privateKeySpace, (short) 0);

        if (expectPinHashEnc) {
            // Need to buffer-pack newPinEnc and pinHashEnc together before verifying
            short readAheadIdx = readIdx;

            Util.arrayCopyNonAtomic(bufferMem, readAheadIdx,
                    outBuf, outOffset, bLen);

            readAheadIdx += bLen;

            if (bufferMem[readAheadIdx++] != 0x06) { // pinHashEnc
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
            }
            if (bufferMem[readAheadIdx++] != 0x50) { // byte array, 16 bytes long
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            Util.arrayCopyNonAtomic(bufferMem, readAheadIdx,
                    outBuf, (short)(outOffset + bLen), (short) 16);

            hmacSha256(privateKeySpace, (short) 0,
                    outBuf, outOffset, (short)(bLen + 16),
                    outBuf, outOffset);
        } else {
            hmacSha256(privateKeySpace, (short) 0,
                    bufferMem, readIdx, bLen,
                    outBuf, outOffset);
        }

        if (Util.arrayCompare(outBuf, outOffset,
                bufferMem, pinAuthIdx, (short) 16) != 0) { // verify only the first 16 bytes, per protocol
            // Messed up crypto or invalid input: cannot proceed
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
        }

        // Verification OK

        return readIdx;
    }

    /**
     * Handles the FIDO2 clientPin initial set subcommand
     *
     * @param apdu Request/response object
     * @param readIdx Read index into request buffer
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleClientPinInitialSet(APDU apdu, short readIdx, short lc) {
        if (pinSet) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        short scratchOff = scratchAlloc((short) 80);

        readIdx = handlePinSetPreamble(apdu, readIdx, lc, scratch, scratchOff, false);

        short unwrapped = sharedSecretUnwrapper.doFinal(bufferMem, readIdx, (short) 64,
                scratch, scratchOff);
        if (unwrapped != 64) {
            throwException(ISO7816.SW_UNKNOWN);
        }
        readIdx += 64;

        short realPinLength = 0;
        for (; realPinLength < 64; realPinLength++) {
            if (scratch[(short)(scratchOff + realPinLength)] == 0x00) {
                break;
            }
        }
        if (realPinLength < 4) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        rawSetPIN(apdu, scratch, scratchOff, realPinLength);

        bufferMem[0] = FIDOConstants.CTAP2_OK;
        doSendResponse(apdu, (short) 1);
    }

    /**
     * Consumes a CBOR object representing the platform's public key from bufferMem.
     *
     * After successful call, DH platform<->authenticator shared secret is available:
     * sharedSecretWrapper and sharedSecretUnwrapper may be used
     *
     * @param apdu Request/response object
     * @param readIdx Index of the platform public key in bufferMem
     *
     * @return New read index position in bufferMem after consuming the key agreement CBOR block
     */
    private short consumeKeyAgreement(APDU apdu, short readIdx) {
        if (bufferMem[readIdx++] != (byte) 0xA5) { // map, with five entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (Util.arrayCompare(bufferMem, readIdx,
                PUBLIC_KEY_DH_ALG_PREAMBLE, (short) 0, (short) PUBLIC_KEY_DH_ALG_PREAMBLE.length) != 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        readIdx += PUBLIC_KEY_DH_ALG_PREAMBLE.length;

        short xIdx = readIdx;
        readIdx += KEY_POINT_LENGTH;
        if (bufferMem[readIdx++] != 0x22) { // map key: y-point
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (bufferMem[readIdx++] != 0x58) { // byte string, one-byte length
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (bufferMem[readIdx++] != KEY_POINT_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short yIdx = readIdx;
        readIdx += KEY_POINT_LENGTH;

        prepareSharedSecret(bufferMem, xIdx, yIdx);
        return readIdx;
    }

    /**
     * Perform the underlying mechanics of setting or changing a PIN. After call,
     * a PIN is set, but the authenticator is in the no-PIN-provided state, and
     * symmetric crypto is unavailable
     *
     * @param apdu Request/response object
     * @param pinBuf Buffer containing raw (unhashed) new PIN
     * @param offset Offset into request buffer of start of PIN
     * @param pinLength Length in bytes of new PIN
     */
    private void rawSetPIN(APDU apdu, byte[] pinBuf, short offset, short pinLength) {
        if (pinSet && !tempBools[IDX_RESET_PIN_PROVIDED]) {
            // We already have a PIN, but we haven't unlocked with it this boot...
            // that's not going to work.
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        // Take the SHA256 of the PIN before we start, and only pass the first 16 bytes to the change function
        // since that's all the protocol sends us to validate the PIN, that is our *real* PIN...
        sha256.doFinal(pinBuf, offset, pinLength,
                pinBuf, offset);

        // Set pinWrapper to use a key we *derived* from the PIN
        // If the PIN is weak, this will modestly increase the difficulty of brute forcing the wrapping key
        PBKDF2(pinBuf, offset, pinBuf, offset);
        Util.arrayCopyNonAtomic(pinBuf, offset, privateKeySpace, (short) 0, (short) 32);
        pinWrapKey.setKey(privateKeySpace, (short) 0);
        Cipher pinWrapper = getAES();
        pinWrapper.init(pinWrapKey, Cipher.MODE_ENCRYPT, wrappingIV, (short) 0, (short) wrappingIV.length);

        // re-encrypt the current wrapping key using the PIN
        // and ATOMICALLY replace the old value with the new one at the same time as we change the PIN itself
        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            if (pinSet) {
                wrappingKey.getKey(wrappingKeySpace, (short) 0);
            }

            pinSet = true;
            tempBools[IDX_RESET_PIN_PROVIDED] = false;
            pinRetryCounter = MAX_PIN_RETRIES;

            // Encrypt the wrapping key with the PIN key
            pinWrapper.doFinal(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length,
                    wrappingKeySpace, (short) 0);

            wrappingKey.clearKey();
            pinWrapKey.clearKey();

            forceInitKeyAgreementKey();

            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }
    }

    /**
     * Implementation of a weakish Password-Based Key Derivation, Version 2 (PBKDF2), as described in RFC2898.
     * After call, the output buffer contains a 32-byte-long key deterministically derived from the incoming PIN.
     *
     * @param pinBuf Buffer containing the (hashed) PIN, 16 bytes long
     * @param offset Offset of PIN in incoming buffer
     * @param outputBuf Buffer into which to write key output
     * @param outputOffset Write offset into output buffer
     */
    private void PBKDF2(byte[] pinBuf, short offset, byte[] outputBuf, short outputOffset) {
        short scratchOff = scratchAlloc((short) 32);
        short scratchKeyOff = scratchAlloc((short) 32);

        Util.arrayCopyNonAtomic(pinKDFSalt, (short) 0,
                scratch, scratchOff, (short) pinKDFSalt.length);
        // PBKDF2 has us concatenate the first iteration number (1) as a 32-bit int onto the end of the salt for iter1
        scratch[(short)(scratchOff + pinKDFSalt.length)] = 0x00;
        scratch[(short)(scratchOff + pinKDFSalt.length + 1)] = 0x00;
        scratch[(short)(scratchOff + pinKDFSalt.length + 2)] = 0x00;
        scratch[(short)(scratchOff + pinKDFSalt.length + 3)] = 0x01;
        for (short i = (short)(pinKDFSalt.length + 5); i < 32; i++) {
            scratch[(short)(scratchOff + i)] = 0x00;
        }

        // Copy the 16 bytes of key and 16 zeroes into the scratch buffer to use as private key
        Util.arrayCopyNonAtomic(pinBuf, offset,
                scratch, scratchKeyOff, (short) 16);
        Util.arrayFillNonAtomic(scratch, (short) (scratchKeyOff + 16), (short) 16, (byte) 0x00);

        for (short i = 0; i < PIN_KDF_ITERATIONS; i++) {
            // Hash the current iteration value with the password-as-private-key HMAC
            hmacSha256(scratch, scratchKeyOff,
                    scratch, scratchOff, (short) 32,
                    scratch, scratchOff);
            if (i == 0) {
                Util.arrayCopyNonAtomic(scratch, scratchOff,
                        outputBuf, outputOffset, (short) 32);
            } else {
                // XOR the previous result with the new one
                for (short j = 0; j < 32; j++) {
                    outputBuf[(short)(j + outputOffset)] = (byte)(outputBuf[(short)(j + outputOffset)] ^ scratch[(short)(j + scratchOff)]);
                }
            }
        }

        scratchRelease((short) 64);
    }

    /**
     * Handle a clientPINGetAgreement CTAP2 request
     *
     * @param apdu The request/response object
     */
    private void handleClientPinGetAgreement(APDU apdu) {
        // Send public key of authenticatorKeyAgreementKey back

        short outputLen = 0;
        bufferMem[outputLen++] = FIDOConstants.CTAP2_OK;
        bufferMem[outputLen++] = (byte) 0xA1; // map - one entry
        bufferMem[outputLen++] = 0x01; // map key: keyAgreement
        bufferMem[outputLen++] = (byte) 0xA5; // map: five entries
        outputLen = Util.arrayCopyNonAtomic(PUBLIC_KEY_DH_ALG_PREAMBLE, (short) 0,
                bufferMem, outputLen, (short) PUBLIC_KEY_DH_ALG_PREAMBLE.length);

        short scratchOff = scratchAlloc((short) (KEY_POINT_LENGTH * 2 + 1));

        ((ECPublicKey) authenticatorKeyAgreementKey.getPublic()).getW(scratch, scratchOff);
        outputLen = writePubKey(outputLen, scratch, (short) (scratchOff + 1));

        doSendResponse(apdu, outputLen);
    }

    /**
     * Handle a clientPINGetRetries CTAP2 request
     *
     * @param apdu The request/response object
     */
    private void handleClientPinGetRetries(APDU apdu) {
        short outputLen = 0;
        bufferMem[outputLen++] = FIDOConstants.CTAP2_OK;
        bufferMem[outputLen++] = (byte) 0xA1; // map - one entry
        bufferMem[outputLen++] = 0x03; // map key: retries
        bufferMem[outputLen++] = (byte) pinRetryCounter;

        doSendResponse(apdu, outputLen);
    }

    /**
     * Forcibly refresh per-boot data. This includes the PIN token and the ephemeral EC pair used for
     * DH between the platform and the authenticator.
     */
    private void forceInitKeyAgreementKey() {
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPrivate());
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPublic());
        authenticatorKeyAgreementKey.genKeyPair();
        keyAgreement.init(authenticatorKeyAgreementKey.getPrivate());

        random.generateData(pinToken, (short) 0, (short) pinToken.length);

        tempBools[IDX_RESET_PLATFORM_KEY_SET] = true;
    }

    /**
     * If the authenticator-to-and-from-platform key agreement hasn't already been set up this boot, set it up
     */
    private void initKeyAgreementKeyIfNecessary() {
        if (!tempBools[IDX_RESET_PLATFORM_KEY_SET]) {
            forceInitKeyAgreementKey();
        }
    }

    /**
     * Gets AES encipherment
     *
     * @return A Cipher set up for AES with an authenticator-supported block size
     */
    private Cipher getAES() {
        // NB: a 128-bit block size is used even for AES256. Just because this says "128"
        // doesn't say anything about the key length
        return Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    /**
     * Platform method called when the applet is deselected. Clears request/response chaining state, etc
     */
    public void deselect() {
        // This one NEEDS to be cleared, because we *might* be using a TRANSIENT_DESELECT private key
        // for the platformKeyAgreementKey. If we are, it'll disappear into the ether after deselect,
        // so we need to make sure that we re-initialize it when we're selected again.
        tempBools[IDX_RESET_PLATFORM_KEY_SET] = false;

        tempShorts[IDX_RP_ITERATION_POINTER] = 0;
        tempShorts[IDX_CRED_ITERATION_POINTER] = 0;
        tempShorts[IDX_CONTINUATION_OUTGOING_WRITE_OFFSET] = 0;
        tempShorts[IDX_CHAINING_INCOMING_READ_OFFSET] = 0;
        tempBools[IDX_RESET_PIN_PROVIDED] = false;
    }

    /**
     * Gets an EC sig object
     *
     * @return An elliptic curve signature object suitable for the FIDO2 standard - ECDSA-SHA256
     */
    private Signature getECSig() {
         return Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    /**
     * Gets an elliptic curve private key object.
     *
     * @return An uninitialized EC private key, ideally in RAM, but in flash if the authenticator doesn't support in-memory
     */
    private ECPrivateKey getECPrivKey() {
        try {
            return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            // Oh well, unsupported, use normal RAM or flash instead
        }

        try {
            return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            // Oh well, unsupported, use flash instead
        }
        return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }

    /**
     * Get a persistent AES key
     *
     * @return An AESKey object that will retain its contents indefinitely
     */
    private AESKey getPersistentAESKey() {
        return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }

    /**
     * Get a transient AES key
     *
     * @return An AESKey object that will go away at power reset
     */
    private AESKey getTransientAESKey() {
        return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    }

    /**
     * When the wrappingKey is correct set up, prepare symmetricWrapper and symmetricUnwrapper.
     * After calling this function, blobs can be wrapped so only we can unwrap them again,
     * or unwrapped after being so wrapped.
     */
    private void initSymmetricCrypto() {
        symmetricWrapper.init(wrappingKey, Cipher.MODE_ENCRYPT, wrappingIV, (short) 0, (short) wrappingIV.length);
        symmetricUnwrapper.init(wrappingKey, Cipher.MODE_DECRYPT, wrappingIV, (short) 0, (short) wrappingIV.length);
    }

    /**
     * Entry point for installing the applet!
     * @param array install parameters array
     * @param offset install parameters offset
     * @param length install parameters length
     * @throws ISOException
     */
    public static void install(byte[] array, short offset, byte length)
            throws ISOException {
        new FIDO2Applet(array, offset, length);
    }

    /**
     * Setup method preparing all the internal state
     *
     * @param array install parameters array
     * @param offset install parameters offset
     * @param length install parameters length
     */
    protected FIDO2Applet(byte[] array, short offset, byte length) {
        // Flash usage
        pinKDFSalt = new byte[28];
        counter = new byte[4];
        wrappingKeySpace = new byte[32];
        wrappingKeyValidation = new byte[64];
        hmacWrapperBytes = new byte[32];
        wrappingIV = new byte[16];
        wrappingKey = getTransientAESKey(); // Our most important treasure, from which all other crypto is born...
        // Resident key data, of course, must all be in flash. Losing that on reset would be Bad
        residentKeyData = new byte[NUM_RESIDENT_KEY_SLOTS * CREDENTIAL_ID_LEN];
        residentKeyValidity = new boolean[NUM_RESIDENT_KEY_SLOTS];
        residentKeyUserIds = new byte[NUM_RESIDENT_KEY_SLOTS * MAX_USER_ID_LENGTH];
        residentKeyUserIdLengths = new byte[NUM_RESIDENT_KEY_SLOTS];
        residentKeyRPIds = new byte[NUM_RESIDENT_KEY_SLOTS * MAX_RESIDENT_RP_ID_LENGTH];
        residentKeyRPIdLengths = new byte[NUM_RESIDENT_KEY_SLOTS];
        residentKeyPublicKeys = new byte[NUM_RESIDENT_KEY_SLOTS * KEY_POINT_LENGTH * 2];
        residentKeyUniqueRP = new boolean[NUM_RESIDENT_KEY_SLOTS];
        numResidentCredentials = 0;
        numResidentRPs = 0;

        // RAM usage - direct buffers
        bufferMem = JCSystem.makeTransientByteArray(BUFFER_MEM_SIZE, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_RESET);
        tempShorts = JCSystem.makeTransientShortArray(NUM_TEMP_SHORTS, JCSystem.CLEAR_ON_DESELECT);
        tempBools = JCSystem.makeTransientBooleanArray(NUM_RESET_BOOLS, JCSystem.CLEAR_ON_DESELECT);
        privateScratch = JCSystem.makeTransientByteArray(PRIVATE_SCRATCH_SIZE, JCSystem.CLEAR_ON_RESET);
        privateKeySpace = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        pinToken = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

        // RAM usage - (ideally) ephemeral keys
        authenticatorKeyAgreementKey = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey()
        );
        ecKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey()
        );
        ecPrivateKey = getECPrivKey();
        pinWrapKey = getTransientAESKey();
        sharedSecretKey = getTransientAESKey();

        // Trivial amounts of flash, object allocations without buffers
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        pinUnwrapper = getAES();
        symmetricWrapper = getAES();
        symmetricUnwrapper = getAES();
        sharedSecretWrapper = getAES();
        sharedSecretUnwrapper = getAES();
        attester = getECSig();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Actual init work
        // Four things are truly random and persist until we hard-FIDO2-reset the authenticator:
        // - the salt we use for deriving keys from PINs
        random.generateData(pinKDFSalt, (short) 0, (short) pinKDFSalt.length);
        // - the IV we use for encrypting and decrypting blobs sent by the authenticator TO the authenticator
        random.generateData(wrappingIV, (short) 0, (short) wrappingIV.length);
        // - the key we use for converting a credential private key into an hmac-secret ... uh ... secret
        random.generateData(hmacWrapperBytes, (short) 0, (short) hmacWrapperBytes.length);
        initKeyAgreementKeyIfNecessary();

        resetWrappingKey();

        // Per-credential keypairs are on the P256 curve
        P256Constants.setCurve((ECKey) ecKeyPair.getPrivate());
        P256Constants.setCurve((ECKey) ecKeyPair.getPublic());

        // Javacard API requires this call to know we succeeded and set the app up with the platform
        register();
    }

}
