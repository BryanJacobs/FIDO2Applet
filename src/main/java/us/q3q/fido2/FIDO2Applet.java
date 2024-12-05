package us.q3q.fido2;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

import javacardx.crypto.Cipher;

/**
 * Core applet class implementing FIDO2 specifications on Javacard
 */
public final class FIDO2Applet extends Applet implements ExtendedLength {

    /**
     * The version of this applet in use
     */
    private static final byte FIRMWARE_VERSION = 0x05;

    /**
     * The AID to which this applet should respond (ignoring any other AIDs sent to it)
     */
    private static final byte[] AID = {
            (byte) 0xA0, 0x00, 0x00, 0x06, 0x47,
            0x2F, 0x00, 0x01
    };

    // Configurable parameters
    /**
     * If set, use low-security keys for everything, to fully comply with the FIDO standards without alwaysUv
     */
    private boolean LOW_SECURITY_MAXIMUM_COMPLIANCE;
    /**
     * The FIDO Alliance certification level obtained by the authenticator as configured
     */
    private byte CERTIFICATION_LEVEL;
    /**
     * If true, default the `alwaysUv` option to on, and prevent disabling it.
     */
    private boolean FORCE_ALWAYS_UV;
    /**
     * If true, the *length* of the user's set PIN is stored, for the `setMinPinLength` extension
     */
    private boolean STORE_PIN_LENGTH;
    /**
     * If true, the authenticator will refuse to reset itself until the following three steps happen in order:
     * <p>
     * 1. a reset command is sent
     * 2. the authenticator is entirely powered off
     * 3. another reset command is sent
     * <p>
     * This is to guard against accidental or malware-driven authenticator resets. It doesn't comply with the FIDO
     * standards. The first reset will respond with OPERATION_DENIED, and if any credential-manipulation commands
     * are received between steps one and three, the process must be started over for the reset to be effective.
     * <p>
     * Note that you still don't need the PIN in order to reset the authenticator: that would defeat the purpose of
     * the full reset...
     */
    private boolean PROTECT_AGAINST_MALICIOUS_RESETS;
    /**
     * If true, credProtect level 0/1/2 (but not 3) resident keys will use the "low security"
     * wrapping key. This improves CTAP2.1 standards compliance, but means those resident keys
     * could be accessed without your PIN in the event of a compromise of the authenticator or
     * a software bug.
     */
    private boolean USE_LOW_SECURITY_FOR_SOME_RKS;
    /**
     * If true, performing ANY operation with a PIN/UV token invalidates it, requiring new
     * authentication for each operation.
     */
    private boolean ONE_USE_PER_PIN_TOKEN;
    /**
     * If true, performing a write with a PIN/UV token invalidates it, requiring new
     * authentication (but not for reading).
     */
    private boolean WRITES_INVALIDATE_PINS;
    /**
     * Maximum size for the in-memory portion of the "scratch" working buffer. Larger will reduce flash use.
     * If this is larger than the available memory, all available memory will be used.
     */
    private short MAX_RAM_SCRATCH_SIZE;
    /**
     * Size of buffer used for receiving incoming data and sending responses.
     * To be standards-compliant, must be at least 1024 bytes, but can be larger.
     */
    private short BUFFER_MEM_SIZE;
    /**
     * Amount of "scratch" working memory in flash
     */
    private short FLASH_SCRATCH_SIZE;
    /**
     * How many resident key slots to allocate in one go
     */
    private static final short NUM_RESIDENT_KEY_SLOTS_PER_BATCH = 10;
    /**
     * Length of initialization vector for key encryption/decryption
     */
    private static final short IV_LEN = 16;
    /**
     * How long an RP identifier is allowed to be for a resident key. Values longer than this are truncated.
     * The CTAP2.1 standard says the minimum value for this is 32.
     */
    private short MAX_RESIDENT_RP_ID_LENGTH;
    /**
     * How long an RP's user identifier is allowed to be - affects storage used by resident keys.
     */
    private static final short MAX_USER_ID_LENGTH = 64;
    /**
     * Maximum number of credBlob bytes to store per resident key
     */
    private byte MAX_CRED_BLOB_LEN;
    /**
     * Number of iterations of PBKDF2 to run on user PINs to get a crypto key.
     * Higher means it's slower to get a PIN token, but also harder to brute force the device open with physical
     * access to it. Can theoretically be any number but surely there are limits to how long you're willing to
     * wait, and there's no way a smartcard is outcompeting a desktop computer...
     */
    private byte PIN_KDF_ITERATIONS;
    /**
     * Number of times PIN entry can be attempted before the device will self-lock. FIDO2 standards say eight.
     */
    private static final byte MAX_PIN_RETRIES = 8;
    /**
     * Maximum number of RPs that can receive the authenticator's configured minPinLength
     */
    private static final byte MAX_RP_IDS_MIN_PIN_LENGTH = 2;
    /**
     * How many times a PIN can be incorrectly entered before the authentiator must be rebooted to proceed.
     * FIDO2 standards say three.
     */
    private static final short PIN_TRIES_PER_RESET = 3;
    /**
     * The maximum number of times we will reroll a private key in makeCredential before giving up
     */
    private static final short MAX_ATTEMPTS_TO_GET_GOOD_KEY = 3;
    /**
     * Maximum amount of the large blob store that can be affected at once
     */
    private static final short MAX_FRAGMENT_LEN = 960;
    /**
     * Byte length of one EC point
     */
    private static final short KEY_POINT_LENGTH = 32;
    /**
     * Byte length of hashed relying party ID
     */
    private static final short RP_HASH_LEN = 32;
    /**
     * Byte length of "payload" part of the FIDO2 Credential ID struct, excluding verification and wrapping
     */
    private static final short CREDENTIAL_PAYLOAD_LEN = (short)(RP_HASH_LEN + KEY_POINT_LENGTH + 16);
    /**
     * Total byte length of output FIDO2 Credential ID struct.
     * Many authenticators use 64, so ideally we would want to use 64 as well so creds that come from this authenticator
     * are not distinguishable from those. However, the FIDO certification standard requires that keys stored inside
     * a credential are authenticated as well as encrypted, so we need some bits for an HMAC.
     * The minimum possible value for non-resident credentials is 32, since credentials need to contain RP
     * ID hashes (which are 32-byte SHA256es). In order to reduce this to 32 you would need to deterministically derive
     * the credential private key from the RP and User IDs instead of storing it inside the credential.
     */
    private static final short CREDENTIAL_ID_LEN = (short)(CREDENTIAL_PAYLOAD_LEN + IV_LEN + 16);
    /**
     * Byte length of an uncompressed EC public key
     */
    private static final short PUB_KEY_LENGTH = (short)(2 * KEY_POINT_LENGTH + 1);
    /**
     * Byte length of hashed client data struct
     */
    private static final short CLIENT_DATA_HASH_LEN = 32;
    /**
     * Required byte length of wrapped incoming PINs. FIDO standards say 64
     */
    private static final short PIN_PAD_LENGTH = 64;
    /**
     * Approximately how much storage, in bytes, each Resident Key will use (upper bound, overestimate)
     */
    private static final short APPROXIMATE_STORAGE_PER_RESIDENT_KEY = 400;

    /**
     * Request/response buffer
     */
    private byte[] bufferMem;
    /**
     * True if the device has been locked with a PIN; false in initial boot state before PIN set
     */
    private boolean pinSet;
    /**
     * Minimum number of UTF-8 code points in PIN
     */
    private byte minPinLength = 4;
    /**
     * Require a PIN change before getting a new PIN token
     */
    private boolean forcePinChange = false;


    // Fields for negotiating auth with the platform
    /**
     * authenticator transient key
     */
    private KeyPair authenticatorKeyAgreementKey;
    /**
     * encrypt/decrypt key to be set based on platform<->authenticator shared secret
     */
    private AESKey sharedSecretAESKey;
    /**
     * verify/hash key to be set based on platform<->authenticator shared secret
     */
    private byte[] sharedSecretVerifyKey;
    /**
     * Random keys for deriving keys for the hmac-secret extension from regular credential private keys
     */
    private final byte[] hmacWrapperBytesUV;
    private final byte[] hmacWrapperBytesNoUV;
    /**
     * Random key for verifying (HMAC-ing) created credentials
     */
    private final byte[] credentialVerificationKey;
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
    private byte[] pinToken;
    /**
     * RP ID associated with (restricting) the PIN token, prefixed by a byte which is 0x01 if RP ID set, 0x00 otherwise
     */
    private byte[] permissionsRpId;
    /**
     * Decrypter used to unwrap data by using a key derived from the user's PIN
     */
    private final Cipher pinUnwrapper;
    /**
     * Encrypter used to wrap data by using a key derived from the user's PIN
     */
    private final Cipher pinWrapper;

    /**
     * per-device salt for deriving keys from PINs
     */
    private final byte[] pinKDFSalt;
    /**
     * key to be set from KDF derivation of PIN
     */
    private AESKey pinWrapKey;
    /**
     * The length (in UTF-8 code points) of the user's PIN
     */
    private short pinCodePointLength;
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
    private final AESKey highSecurityWrappingKey;
    /**
     * Authenticator-specific master key used for situations where a PIN cannot be presented.
     * This key is never used for credProtect level 3 keys unless LOW_SECURITY_MAXIMUM_COMPLIANCE is set.
     * If FORCE_ALWAYS_UV is set, it's used for all keys.
     */
    private final AESKey lowSecurityWrappingKey;
    /**
     * random IV for authenticator private wrapping with highSecurityWrappingKey
     */
    private final byte[] highSecurityWrappingIV;
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
    private final SigOpCounter counter;
    /**
     * Value that decreases with each failed PIN guess
     */
    private final PinRetryCounter pinRetryCounter;

    // Parameters for the real elliptic-curve keys :-)
    /**
     * The actual per-credential key pair
     */
    private KeyPair ecKeyPair;
    /**
     * Used for CTAP2 "basic" attestation, and for CTAP1/U2F
     */
    private ECPrivateKey attestationKey;
    /**
     * If set to true, allow loading an attestation certificate.
     * Will become false after cert installed.
     */
    private boolean attestationSwitchingEnabled;
    /**
     * Used for CTAP2 "basic" attestation - should be a CBOR array
     * where each element contains X.509 certificate data, starting
     * with the basic attestation certificate
     */
    private byte[] attestationData;
    /**
     * How much of the attestationData has been successfully read so far
     */
    private short filledAttestationData;
    /**
     * General hashing of stuff
     */
    private final MessageDigest sha256;
    /**
     * Used to make sure the user REALLY wants to reset their authenticator
     */
    private boolean resetRequested;
    /**
     * Set to true when the use of a PIN is forced for all operations
     */
    private boolean alwaysUv;
    /**
     * Whether enterprise attestation is """enabled"""
     */
    private boolean enterpriseAttestation = false;
    /**
     * Everything that needs to be hot in RAM instead of stored to the flash. All goes away on deselect or reset!
     */
    private final TransientStorage transientStorage;
    /**
     * Same, but for managed buffers
     */
    private BufferManager bufferManager;

    /**
     * Resident Keys
     */
    private ResidentKeyData[] residentKeys;

    // Data storage for things other than resident keys
    /**
     * Encrypted RPID hashes used for the minPinLength extension
     */
    private final byte[] minPinRPIDs;
    /**
     * How many resident key slots are filled
     */
    private byte numResidentCredentials;
    /**
     * How many distinct RPs are present across all resident keys
     */
    private byte numResidentRPs;
    /**
     * Storage for the largeBlobs extension
     */
    private final byte[] largeBlobStoreA;
    private final byte[] largeBlobStoreB;
    /**
     * Which large blob store is in use
     */
    private byte largeBlobStoreIndex = 0;
    /**
     * Length of the currently stored large-blob array
     */
    private short largeBlobStoreFill;

    /**
     * Unique identifier ID - set on loading an attestation,
     * certificate, or left zeroes for self-attestation.
     */
    private final byte[] aaguid = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /**
     * Deliver a particular byte array to the platform
     *
     * @param apdu  Request/response object
     * @param array Bytes to send
     * @param len   Length to send, starting at byte zero
     */
    private static void sendByteArray(APDU apdu, byte[] array, short len) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(array, (short) 0, buffer, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Sends bytes which are already in the APDU buffer
     *
     * @param apdu Request/response object
     * @param len  Length of content to send
     */
    private void sendNoCopy(APDU apdu, short len) {
        bufferManager.clear();
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Sends a CTAP error (not an ISO7816 error!) to the platform.
     * Also resets any APDU chaining state.
     *
     * @param apdu Request/response object
     * @param sendByte Byte representing the CTAP error state
     */
    private void sendErrorByte(APDU apdu, byte sendByte) {
        transientStorage.clearIterationPointers();
        bufferManager.clear(); // Just in case

        byte[] buffer = apdu.getBuffer();
        buffer[0] = sendByte;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        throwException(ISO7816.SW_NO_ERROR);
    }

    /**
     * Fully read an incoming request into either the APDU buffer or bufferMem. In the event the request is larger
     * than the buffer, throws an exception. After call, request chaining variables will
     * be set appropriately if the request is part of a chained sequence.
     *
     * @param apdu Request/response object
     * @param lc Length of request received from the platform
     * @param amtRead Amount of the request already read into the APDU buffer
     *
     * @return Buffer which contains the request data (bufferMem or given APDU buffer object)
     */
    private byte[] fullyReadReq(APDU apdu, short lc, short amtRead, boolean forceBuffering) {
        byte[] buffer = apdu.getBuffer();

        transientStorage.clearAssertIterationPointer();
        final short chainOff = transientStorage.getChainIncomingReadOffset();
        final boolean extendedAPDU = apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA;

        final boolean packInAPDU = !forceBuffering && (!extendedAPDU || (
                chainOff == 0 && ((short)(buffer.length) < 0 || lc <= (short)(buffer.length - 3))
        ));

        if (packInAPDU) {
            // Single-buffer packed case
            // Shift down so meaningful data start at offset 0
            Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(),
                    buffer, (short) 0, amtRead);
            while (amtRead < lc) {
                short read = apdu.receiveBytes(amtRead);
                if (read == 0) {
                    throwException(ISO7816.SW_WRONG_LENGTH);
                }
                amtRead += read;
            }
            if (amtRead != lc) {
                throwException(ISO7816.SW_WRONG_LENGTH);
            }
            transientStorage.resetChainIncomingReadOffset();
            return buffer;
        }

        // Buffering read case
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(),
                bufferMem, chainOff, amtRead);

        short curRead = amtRead;
        while (curRead < lc) {
            short read = apdu.receiveBytes((short) 0);

            if (read == 0) {
                throwException(ISO7816.SW_WRONG_LENGTH);
            }

            if (curRead > (short) (bufferMem.length - read)) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            Util.arrayCopyNonAtomic(buffer, (short) 0,
                    bufferMem, (short) (curRead + chainOff), read);
            curRead = (short) (curRead + read);
        }

        // Since we just offloaded the whole APDU into buffer memory, it's entirely available for scratch usage
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

        if (curRead > lc) {
            transientStorage.resetChainIncomingReadOffset();
            throwException(ISO7816.SW_WRONG_LENGTH);
        }

        if (!apdu.isCommandChainingCLA()) {
            transientStorage.resetChainIncomingReadOffset();
        }

        return bufferMem;
    }

    /**
     * If the given byte represents a CBOR map, return the number of entries in that map.
     * Otherwise, return an error to the platform.
     *
     * @param apdu Request/response object
     * @param cborMapDeclaration Byte declaring a CBOR map
     *
     * @return The number of map entries in the given CBOR object
     */
    private short getMapEntryCount(APDU apdu, byte cborMapDeclaration) {
        short sb = ub(cborMapDeclaration);
        if (sb < 0x00A0 || sb > 0x00B7) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        return (short)(sb - 0x00A0);
    }

    /**
     * Implements the core FIDO2 CTAP2 makeCredential API
     *
     * @param apdu   Request/response object
     * @param lc     Length of the request, as sent by the platform
     * @param buffer Byte buffer containing input request
     */
    private void makeCredential(APDU apdu, short lc, byte[] buffer) {
        short readIdx = 1;

        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (resetRequested) {
            resetRequested = false;
        }

        final short numParameters = getMapEntryCount(apdu, buffer[readIdx++]);
        if (numParameters < 4) { // There's no valid makeCredential call with fewer than four params
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (buffer[readIdx++] != 0x01) { // clientDataHash
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (buffer[readIdx++] == 0x58) {
            // one-byte length, then bytestr
            if (buffer[readIdx++] != CLIENT_DATA_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short clientDataHashIdx = readIdx;
        readIdx += CLIENT_DATA_HASH_LEN; // we checked above this is indeed the length of the client data hash
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (buffer[readIdx++] != 0x02) { // rp
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        readIdx = consumeMapAndGetID(apdu, buffer, readIdx, lc, false, false, true, false);
        final short rpIdIdx = transientStorage.getStoredIdx();
        short rpIdLen = transientStorage.getStoredLen();

        if (buffer[readIdx++] != 0x03) { // user
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        final short userMapIdx = readIdx;
        readIdx = consumeMapAndGetID(apdu, buffer, readIdx, lc, true, false, true, false);
        final short userIdIdx = transientStorage.getStoredIdx();
        final byte userIdLen = transientStorage.getStoredLen();
        if (userIdLen > MAX_USER_ID_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }
        consumeMapAndGetID(apdu, buffer, userMapIdx, lc, false, false, true, true);
        final short userNameIdx = transientStorage.getStoredIdx();
        final byte userNameLen = transientStorage.getStoredLen();

        if (buffer[readIdx++] != 0x04) { // pubKeyCredParams
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        final byte pubKeyCredParamsType = buffer[readIdx++];
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if ((pubKeyCredParamsType & 0xF0) != 0x80) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        // We only support one algorithm, so let's find that one.
        boolean foundES256 = false;
        final short numPubKeys = (short)(pubKeyCredParamsType & 0x0F);
        for (short i = 0; i < numPubKeys; i++) {
            readIdx = checkIfPubKeyBlockSupported(apdu, buffer, readIdx, lc);
            if (transientStorage.getStoredLen() != -1) {
                foundES256 = true;
                // cannot break here because we need to check for any
                // invalid pubKeyCredParams entries that come later...
            }
        }

        if (!foundES256) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        boolean hmacSecretEnabled = false;
        boolean uvmRequested = false;
        byte credProtectLevel = 0;
        boolean pinAuthSuccess = false;

        defaultOptions();

        short excludeListStartIdx = -1;
        short numExcludeListEntries = 0;
        byte pinProtocol = 1;
        short pinAuthIdx = -1;
        short credBlobIdx = -1;
        byte credBlobLen = 0;
        boolean largeBlobKeyRequested = false;
        boolean minPinRequested = false;

        // Consume any remaining parameters
        byte lastMapKey = 0x04;
        for (short i = 4; i < numParameters; i++) {
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (buffer[readIdx] <= lastMapKey) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            lastMapKey = buffer[readIdx];

            short excludeListTypeVal, numExtensions, sLen, j;
            switch (buffer[readIdx++]) {
                case 0x05: // excludeList
                    excludeListTypeVal = ub(buffer[readIdx]);
                    if (!(excludeListTypeVal >= 0x0080 && excludeListTypeVal <= 0x0097)) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }

                    numExcludeListEntries = (short)(excludeListTypeVal - 0x80);
                    excludeListStartIdx = (short)(readIdx + 1);
                    break;
                case 0x06: // extensions
                    numExtensions = getMapEntryCount(apdu, buffer[readIdx++]);
                    for (j = 0; j < numExtensions; j++) {
                        if (!(buffer[readIdx] >= 0x0061 && buffer[readIdx] <= 0x0077)) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        }
                        sLen = (short) (buffer[readIdx] - 0x60);
                        readIdx++;
                        if (readIdx >= (short)(lc - sLen)) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                        }
                        if (sLen == CannedCBOR.HMAC_SECRET_EXTENSION_ID.length &&
                                Util.arrayCompare(buffer, readIdx,
                                        CannedCBOR.HMAC_SECRET_EXTENSION_ID, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            if (buffer[readIdx] != (byte) 0xF5 && buffer[readIdx] != (byte) 0xF4) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                            }
                            hmacSecretEnabled = buffer[readIdx++] == (byte) 0xF5;
                        } else if (sLen == CannedCBOR.CRED_PROTECT_EXTENSION_ID.length &&
                                Util.arrayCompare(buffer, readIdx,
                                        CannedCBOR.CRED_PROTECT_EXTENSION_ID, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            credProtectLevel = buffer[readIdx++];
                            if (credProtectLevel != 0x01 && credProtectLevel != 0x02 && credProtectLevel != 0x03) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                            }
                        } else if (sLen == CannedCBOR.CRED_BLOB_EXTENSION_ID.length &&
                                Util.arrayCompare(buffer, readIdx,
                                        CannedCBOR.CRED_BLOB_EXTENSION_ID, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            credBlobIdx = readIdx;
                            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                            if (readIdx >= lc || readIdx < credBlobIdx) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                            }
                            if (buffer[credBlobIdx] >= 0x40 && buffer[credBlobIdx] <= 0x57) {
                                credBlobLen = (byte)(buffer[credBlobIdx++] - 0x40);
                            } else if (buffer[credBlobIdx] == 0x58) {
                                credBlobLen = buffer[++credBlobIdx];
                                credBlobIdx++;
                            } else {
                                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                            }
                        } else if (sLen == CannedCBOR.LARGE_BLOB_EXTENSION_ID.length &&
                                Util.arrayCompare(buffer, readIdx,
                                        CannedCBOR.LARGE_BLOB_EXTENSION_ID, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            if (buffer[readIdx] == (byte) 0xF4) {
                                // largeBlobKey must be true if present
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                            } else if (buffer[readIdx] != (byte) 0xF5) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                            }
                            readIdx++;
                            largeBlobKeyRequested = true;
                        } else if (sLen == CannedCBOR.MIN_PIN_LENGTH.length &&
                                Util.arrayCompare(buffer, readIdx,
                                    CannedCBOR.MIN_PIN_LENGTH, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            if (buffer[readIdx] == (byte) 0xF4) {
                                // setMinPin must be true if present
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                            } else if (buffer[readIdx] != (byte) 0xF5) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                            }
                            minPinRequested = true;
                            readIdx++;
                        } else if (sLen == CannedCBOR.UVM_EXTENSION_ID.length &&
                                Util.arrayCompare(buffer, readIdx,
                                        CannedCBOR.UVM_EXTENSION_ID, (short) 0, sLen) == 0) {
                            readIdx += sLen;
                            if (buffer[readIdx] == (byte) 0xF4) {
                                // uvm must be true if present
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                            } else if (buffer[readIdx] != (byte) 0xF5) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                            }
                            readIdx++;
                            uvmRequested = true;
                        } else {
                            readIdx += sLen;
                            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                            if (readIdx >= lc) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                            }
                        }
                    }
                    continue;
                case 0x07: // options
                    readIdx = processOptionsMap(apdu, buffer, readIdx, lc, true, true);
                    continue;
                case 0x08: // pinAuth
                    // Read past this, because we need the pinProtocol option first
                    pinAuthIdx = readIdx;
                    break;
                case 0x09: // pinProtocol
                    pinProtocol = buffer[readIdx++];
                    checkPinProtocolSupported(apdu, pinProtocol);
                    continue;
                case 0x0A: // enterpriseAttestation
                    // When "disabled", reject the parameter; when "enabled", ignore it
                    if (!enterpriseAttestation) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    byte val = buffer[readIdx++];
                    if (val != 0x01 && val != 0x02) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                    }
                    break;
                default:
                    break;
            }

            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
        }

        if (!transientStorage.hasRKOption()) {
            if (largeBlobKeyRequested) {
                // Large blob keys are only for RKs
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
            }

            // we won't store cred blobs on non-RKs
            credBlobLen = (byte)(MAX_CRED_BLOB_LEN + 1);
        }

        if (pinAuthIdx != -1) {
            if (buffer[pinAuthIdx] == 0x40) {
                // For CTAP2.0 compatibility: just checking which authenticator to use
                if (pinSet) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
                }
            }

            // Come back and verify PIN auth
            byte pinPermissions = transientStorage.getPinPermissions();

            verifyPinAuth(apdu, buffer, pinAuthIdx, buffer, clientDataHashIdx, pinProtocol, true);

            if ((pinPermissions & FIDOConstants.PERM_MAKE_CREDENTIAL) == 0) {
                // PIN token doesn't have permission for the MC operation
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            }

            if (WRITES_INVALIDATE_PINS) {
                transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
            }

            pinAuthSuccess = true;
        }

        if (!pinAuthSuccess) {
            if (alwaysUv || (pinSet && transientStorage.hasRKOption() && !USE_LOW_SECURITY_FOR_SOME_RKS)) {
                // PIN is set, but no PIN-auth option was provided
                // OR: PIN not set, but we've been asked not to do this without one
                if (pinSet) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
                }
            }
        }
        loadWrappingKeyIfNoPIN();

        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.ANYWHERE);
        final short scratchRPIDHashOffset = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashOffset);

        if (pinAuthSuccess) {
            if (permissionsRpId[0] == 0x00) {
                // No permissions RP ID set - we got this PIN token using default permissions.
                // We can proceed here, but we need to bind the current PIN token to this RP ID now.
                permissionsRpId[0] = 0x01;
                Util.arrayCopyNonAtomic(scratchRPIDHashBuffer, scratchRPIDHashOffset,
                        permissionsRpId, (short) 1, RP_HASH_LEN);
            } else {
                // Permissions RP ID is set - check it
                if (Util.arrayCompare(scratchRPIDHashBuffer, scratchRPIDHashOffset,
                        permissionsRpId, (short) 1, RP_HASH_LEN) != 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
        }
        if (minPinRequested) {
            // Check RP is authorized to receive minPinLength
            boolean ok = false;
            for (short i = 0; i < MAX_RP_IDS_MIN_PIN_LENGTH; i++) {
                if (Util.arrayCompare(scratchRPIDHashBuffer, scratchRPIDHashOffset,
                        minPinRPIDs, (short)(i * RP_HASH_LEN), RP_HASH_LEN) == 0) {
                    ok = true;
                    break;
                }
            }
            minPinRequested = ok;
        }

        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);

        // Check excludeList. This is deferred to here so it's after we check PIN auth...
        if (numExcludeListEntries > 0) {
            boolean willExclude = false;
            short excludeReadIdx = excludeListStartIdx;
            for (short excludeListIdx = 0; excludeListIdx < numExcludeListEntries; excludeListIdx++) {
                excludeReadIdx = consumeMapAndGetID(apdu, buffer, excludeReadIdx, lc, true, true, false, false);

                if (willExclude) {
                    // We already know we're going to return EXCLUDED, so don't bother decrypting more
                    continue;
                }

                final short credIdIdx = transientStorage.getStoredIdx();
                final short credIdLen = transientStorage.getStoredLen();
                if (credIdLen != CREDENTIAL_ID_LEN) {
                    // ruh-roh, the exclude list has bogus stuff in it...
                    // it could be a credential ID from some OTHER authenticator, so ignore it.
                    continue;
                }

                final short rkIndex = scanRKsForExactCredential(buffer, credIdIdx);

                if (checkCredential(apdu, buffer, credIdIdx, CREDENTIAL_ID_LEN,
                        scratchRPIDHashBuffer, scratchRPIDHashOffset,
                        scratchCredBuffer, scratchCredOffset, rkIndex, (byte)(pinAuthSuccess ? 3 : 2))) {
                    // This credential is valid. Don't fail early,
                    // because the compliance test requires us to report later invalid entries.
                    willExclude = true;
                }
            }

            if (willExclude) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }

        if (!LOW_SECURITY_MAXIMUM_COMPLIANCE && pinSet
                && transientStorage.getPinProtocolInUse() == 0 && credProtectLevel > 2) {
            // Can't make level-three creds without access to the wrapping key for them!
            // This is the actual purpose of the LOW_SECURITY_MAXIMUM_COMPLIANCE flag
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        // Done getting params - make a keypair. You know, what we're supposed to do in this function?
        // Well, we're getting to it, only 150 lines in.
        // We sometimes reset the private key, which clears its curve data, so reset that here
        P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());

        final short scratchPublicKeyHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH, BufferManager.ANYWHERE);
        final short scratchPublicKeyOffset = bufferManager.getOffsetForHandle(scratchPublicKeyHandle);
        final byte[] scratchPublicKeyBuffer = bufferManager.getBufferForHandle(apdu, scratchPublicKeyHandle);

        if (!makeGoodKeyPair(ecKeyPair, scratchPublicKeyBuffer, scratchPublicKeyOffset)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
        }

        short targetRKSlot = -1;

        // if we're making a resident key, we need to, you know, save that for later
        if (transientStorage.hasRKOption()) {
            final short scratchUserIdHandle = bufferManager.allocate(apdu, MAX_USER_ID_LENGTH, BufferManager.ANYWHERE);
            final short scratchUserIdOffset = bufferManager.getOffsetForHandle(scratchUserIdHandle);
            final byte[] scratchUserIdBuffer = bufferManager.getBufferForHandle(apdu, scratchUserIdHandle);

            boolean foundMatchingRK = false;
            boolean foundRPMatchInRKs = false;
            if (numResidentCredentials == 0) {
                // Short circuit for first RK: use the first slot, duh. Don't bother to scan a huge invalid array.
                targetRKSlot = 0;
            } else {
                for (short i = 0; i < (short) residentKeys.length; i++) {
                    if (residentKeys[i] == null) {
                        targetRKSlot = i;
                        break;
                    }

                    // Fixed maxCredProtectLevel=3 below would allow clobbering high-security credentials
                    // even when we haven't PIN-authenticated...
                    if (checkCredential(
                            apdu, i, scratchRPIDHashBuffer, scratchRPIDHashOffset,
                            scratchCredBuffer, scratchCredOffset, (byte)(pinAuthSuccess ? 3 : 1))) {
                        // This credential matches the RP we're looking at.
                        foundRPMatchInRKs = true;

                        // ... but it might not match the user ID we're requesting...
                        if (userIdLen == residentKeys[i].getUserIdLength()) {
                            // DECRYPT the encrypted user ID we stored for this RK, so we can compare
                            AESKey key = getAESKeyForExistingRK(i);
                            residentKeys[i].unpackUserID(key, symmetricUnwrapper, scratchUserIdBuffer, scratchUserIdOffset);

                            if (Util.arrayCompare(
                                    buffer, userIdIdx,
                                    scratchUserIdBuffer, scratchUserIdOffset, userIdLen
                            ) == 0) {
                                // ... this credential is a perfect match - overwrite it
                                foundMatchingRK = true;
                                targetRKSlot = i;
                                break;
                            }
                        }
                    }
                }
            }

            short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);

            if (targetRKSlot == -1) {
                // We're entirely full up...
                // let's allocate some more space, if we can!

                short oldSize = (short) residentKeys.length;
                short newSize = (short)(oldSize + NUM_RESIDENT_KEY_SLOTS_PER_BATCH);

                if (availableMem >= 0 && availableMem < (short)(newSize * 16)) {
                    // Too close to the limit for safety
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
                }

                try {
                    ResidentKeyData[] newStore = new ResidentKeyData[newSize];
                    for (short i = 0; i < (short) residentKeys.length; i++) {
                        newStore[i] = residentKeys[i];
                    }
                    residentKeys = newStore;
                    targetRKSlot = oldSize; // first slot in the new store
                } catch (Exception e) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
                }
                try {
                    JCSystem.requestObjectDeletion();
                } catch (Exception e) {
                    // Do nothing - waste a tiny amount of memory
                }

                // Re-get available mem here, because we used/freed some
                availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);

            }

            if (availableMem >= 0 && availableMem < APPROXIMATE_STORAGE_PER_RESIDENT_KEY) {
                // No room to create a new resident key without first deleting one
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
            }

            // Stow the new credential in the slot we chose earlier
            // we will need the zero-padded user ID
            Util.arrayCopyNonAtomic(buffer, userIdIdx, scratchUserIdBuffer, scratchUserIdOffset, userIdLen);
            if (userIdLen < MAX_USER_ID_LENGTH) {
                Util.arrayFillNonAtomic(scratchUserIdBuffer, (short)(scratchUserIdOffset + userIdLen),
                        (short)(MAX_USER_ID_LENGTH - userIdLen), (byte) 0x00);
            }

            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                // Set flag byte first, so encryption stuff below can use it
                byte effectiveCPLevel = credProtectLevel;
                if (effectiveCPLevel == 0) {
                    // "default" creds are saved as level one
                    effectiveCPLevel = 1;
                }
                boolean uniqueRP = false;
                if (!foundMatchingRK) {
                    // We're filling an empty slot
                    numResidentCredentials++;
                    if (!foundRPMatchInRKs) {
                        uniqueRP = true;
                    }
                } else if (targetRKSlot < (short)(numResidentCredentials - 1)) {
                    // We need to put the credential at the end of the list so it's still the "most recent" one
                    for (short i = targetRKSlot; i < (short)(numResidentCredentials - 1); i++) {
                        residentKeys[i] = residentKeys[(short)(i + 1)];
                    }
                    targetRKSlot = (short)(numResidentCredentials - 1);
                }

                byte effectiveCredBlobLen = credBlobLen;
                if (effectiveCredBlobLen > MAX_CRED_BLOB_LEN) {
                    // Ignore
                    effectiveCredBlobLen = 0;
                }

                final boolean lowSecForRK = USE_LOW_SECURITY_FOR_SOME_RKS && credProtectLevel < 3;
                final boolean lowSecWasUsed = encodeCredentialID(apdu, (ECPrivateKey) ecKeyPair.getPrivate(),
                        scratchRPIDHashBuffer, scratchRPIDHashOffset,
                        scratchCredBuffer, scratchCredOffset,
                        targetRKSlot, lowSecForRK, credProtectLevel);

                final AESKey key = lowSecWasUsed ? lowSecurityWrappingKey : highSecurityWrappingKey;

                residentKeys[targetRKSlot] = new ResidentKeyData(
                        random, key, symmetricWrapper,
                        scratchPublicKeyBuffer, (short)(scratchPublicKeyOffset + 1), (short)(KEY_POINT_LENGTH * 2),
                        buffer, credBlobIdx, effectiveCredBlobLen,
                        uniqueRP
                );
                residentKeys[targetRKSlot].setEncryptedCredential(scratchCredBuffer, scratchCredOffset,
                        CREDENTIAL_ID_LEN, effectiveCPLevel, !lowSecWasUsed);

                residentKeys[targetRKSlot].setUser(key, symmetricWrapper,
                        scratchUserIdBuffer, scratchUserIdOffset, userIdLen,
                        buffer, userNameIdx, userNameLen);
                // Carefully manage buffers since we only need one of (user, RPID) at a time!
                bufferManager.release(apdu, scratchUserIdHandle, MAX_USER_ID_LENGTH);

                final short scratchResidentRPIDHandle = bufferManager.allocate(apdu, MAX_RESIDENT_RP_ID_LENGTH, BufferManager.ANYWHERE);
                final short scratchResidentRPIDOffset = bufferManager.getOffsetForHandle(scratchResidentRPIDHandle);
                final byte[] scratchResidentRPIdBuffer = bufferManager.getBufferForHandle(apdu, scratchResidentRPIDHandle);

                rpIdLen = truncateRPId(buffer, rpIdIdx, rpIdLen,
                        scratchResidentRPIdBuffer, scratchResidentRPIDOffset);

                residentKeys[targetRKSlot].setRpId(key, symmetricWrapper,
                        scratchResidentRPIdBuffer, scratchResidentRPIDOffset, (byte) rpIdLen);

                bufferManager.release(apdu, scratchResidentRPIDHandle, MAX_RESIDENT_RP_ID_LENGTH);

                if (!foundRPMatchInRKs) {
                    numResidentRPs++;
                }

                ok = true;
            } catch (Exception e) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
            } finally {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        } else {
            // Non-resident credProtect Level 3 creds still need to use the high security key (to require PIN auth)
            final boolean credMayUseLowSecurityForDiscoverable = credProtectLevel < 3;
            encodeCredentialID(apdu, (ECPrivateKey) ecKeyPair.getPrivate(),
                    scratchRPIDHashBuffer, scratchRPIDHashOffset,
                    scratchCredBuffer, scratchCredOffset,
                    (short) -1, credMayUseLowSecurityForDiscoverable, credProtectLevel);
        }

        // OKAY! time to start actually making the credential and sending a response!
        final short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, BufferManager.ANYWHERE);
        final short clientDataHashScratchOffset = bufferManager.getOffsetForHandle(clientDataHashHandle);
        final byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        Util.arrayCopyNonAtomic(buffer, clientDataHashIdx,
                clientDataHashBuffer, clientDataHashScratchOffset, CLIENT_DATA_HASH_LEN);

        // Everything we need is out of the input
        // We're now okay to use the whole bufferMem space to build and send our reply
        short outputLen = 0;
        bufferMem[outputLen++] = 0x00; // status - OK!
        bufferMem[outputLen++] = (byte) (largeBlobKeyRequested ? 0xA4 : 0xA3); // Map - three or four keys

        outputLen = Util.arrayCopyNonAtomic(CannedCBOR.MAKE_CREDENTIAL_RESPONSE_PREAMBLE, (short) 0,
                bufferMem, outputLen, (short) CannedCBOR.MAKE_CREDENTIAL_RESPONSE_PREAMBLE.length);


        // set bit 0 for user present
        // set bit 6 for attestation included (always, for a makeCredential)
        byte flags = transientStorage.hasUPOption() ? (byte) 0x41 : 0x40;
        if (pinAuthSuccess) {
            // set bit 2 for user verified
            flags = (byte)(flags | 0x04);
        }

        // CBOR requires us to know how long authData is before we can start writing it out...
        // ... so let's calculate that
        final short adLen = getAuthDataLen(true, hmacSecretEnabled,
                credProtectLevel > 0,
                credBlobIdx != -1, uvmRequested, minPinRequested, flags);

        if (hmacSecretEnabled || credProtectLevel > 0 || credBlobIdx != -1 || uvmRequested || minPinRequested) {
            // set bit 7 for extensions
            flags = (byte)(flags | 0x80);
        }

        final short adAddlBytes = writeAD(bufferMem, outputLen, adLen, scratchRPIDHashBuffer, scratchRPIDHashOffset,
                scratchPublicKeyBuffer, (short)(scratchPublicKeyOffset + 1), flags, hmacSecretEnabled, credProtectLevel,
                uvmRequested, minPinRequested, (byte) (credBlobIdx != -1 ? (credBlobLen <= MAX_CRED_BLOB_LEN ? 1 : -1) : 0),
                scratchCredBuffer, scratchCredOffset);

        final short offsetForStartOfAuthData = (short) (outputLen + adAddlBytes);
        outputLen = (short)(outputLen + adLen + adAddlBytes);

        // TEMPORARY copy to build signing buffer
        Util.arrayCopyNonAtomic(clientDataHashBuffer, clientDataHashScratchOffset,
                bufferMem, outputLen, CLIENT_DATA_HASH_LEN);

        boolean selfAttestation = attestationKey == null;
        byte[] attestationPreamble;
        if (selfAttestation) {
            attester.init(ecKeyPair.getPrivate(), Signature.MODE_SIGN);
            attestationPreamble = CannedCBOR.SELF_ATTESTATION_STATEMENT_PREAMBLE;
        } else {
            attester.init(attestationKey, Signature.MODE_SIGN);
            attestationPreamble = CannedCBOR.BASIC_ATTESTATION_STATEMENT_PREAMBLE;
        }
        final short sigLength = attester.sign(bufferMem, offsetForStartOfAuthData, (short)(adLen + CLIENT_DATA_HASH_LEN),
                bufferMem, (short) (outputLen + attestationPreamble.length + 2));

        // EC key pair COULD be stored in flash (if device doesn't support transient EC privKeys), so might as
        // well clear it out here since we don't need it anymore. We'll get its private key back from the credential
        // ID to use later...
        ecKeyPair.getPrivate().clearKey();

        // Attestation statement
        outputLen = Util.arrayCopyNonAtomic(attestationPreamble, (short) 0,
                bufferMem, outputLen, (short) attestationPreamble.length);

        if (sigLength < 24) {
            // We won't be needing that extra byte... shift the signature back one byte
            Util.arrayCopyNonAtomic(bufferMem, (short)(outputLen + 2),
                    bufferMem, (short)(outputLen + 1), sigLength);
        } else if (sigLength > 255) {
            // We'll be needing an EXTRA byte! This doesn't happen with ES256 signatures though.
            Util.arrayCopyNonAtomic(bufferMem, (short)(outputLen + 2),
                    bufferMem, (short)(outputLen + 3), sigLength);
        }

        outputLen = encodeIntLenTo(bufferMem, outputLen, sigLength, true);
        outputLen += sigLength;

        if (!selfAttestation) {
            // Add x5c certificate data
            outputLen = Util.arrayCopyNonAtomic(CannedCBOR.X5C, (short) 0,
                    bufferMem, outputLen, (short) CannedCBOR.X5C.length);

            // The certificates can be very (VERY) long. So we set up the
            // output delivery to read directly from the X5C buffer.
            transientStorage.setStreamX5CLater(largeBlobKeyRequested);
            if (largeBlobKeyRequested) {
                // Unfortunately the large blob key comes after the very long x5c data...
                // Park the LBK in the upper 32 bytes of bufferMem
                if (targetRKSlot == -1) {
                    // How did we get here without making an RK?
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
                }
                if (outputLen >= (short)(bufferMem.length - 35)) {
                    // No room in the buffer with such a huge response payload
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
                }
                bufferMem[(short)(bufferMem.length - 36)] = 0x05; // map key: largeBlobKey
                bufferMem[(short)(bufferMem.length - 35)] = 0x58; // array, one-byte length
                bufferMem[(short)(bufferMem.length - 34)] = (byte) 32; // 32 bytes of LBK
                residentKeys[targetRKSlot].emitLargeBlobKey(getAESKeyForExistingRK(targetRKSlot), symmetricWrapper,
                        bufferMem, (short)(bufferMem.length - 33));
            }
        } else if (largeBlobKeyRequested) {
            bufferMem[outputLen++] = 0x05; // map key: largeBlobKey
            bufferMem[outputLen++] = 0x58; // array, one-byte length
            bufferMem[outputLen++] = (byte) 32; // 32 bytes of LBK
            residentKeys[targetRKSlot].emitLargeBlobKey(getAESKeyForExistingRK(targetRKSlot), symmetricWrapper,
                    bufferMem, outputLen);
            outputLen += 32;
        }

        doSendResponse(apdu, outputLen);
    }


    /**
     * Creates a "good" (32-byte-private-key) EC keypair.
     *
     * @param keyPair After call, this is set to a usable keypair. Before call, must be initialized with P256
     *                curve points.
     * @param publicKeyBuffer Buffer into which to write the public key - must have PUBLIC_KEY_LENGTH bytes available.
     *                        If null, keypair will be created "blind" and public key not stored anywhere.
     * @param publicKeyOffset Offset into write buffer
     * @return true if successful, false if not.
     */
    private boolean makeGoodKeyPair(KeyPair keyPair, byte[] publicKeyBuffer, short publicKeyOffset) {
        for (short i = 1; i <= MAX_ATTEMPTS_TO_GET_GOOD_KEY; i++) {
            keyPair.genKeyPair();

            if (publicKeyBuffer == null) {
                // No memory to check key lengths
                return true;
            }
            // Sometimes, when the stars (mis)align, we get points less than 32 bytes long.
            // Let's roll the dice up to three times to make that happen less.
            short sLen = ((ECPrivateKey) keyPair.getPrivate()).getS(publicKeyBuffer, publicKeyOffset);
            short wLen = ((ECPublicKey) keyPair.getPublic()).getW(publicKeyBuffer, publicKeyOffset);
            if (sLen == KEY_POINT_LENGTH && wLen == PUB_KEY_LENGTH
                    && publicKeyBuffer[publicKeyOffset] == 0x04) {
                return true;
            }
        }
        return false;
    }

    /**
     * If, and only if, no PIN is set, directly initialize symmetric crypto
     * from our flash-stored wrapping key (which should be unencrypted)
     */
    private void loadWrappingKeyIfNoPIN() {
        if (!pinSet) {
            highSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
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
        if (rpIdLen <= MAX_RESIDENT_RP_ID_LENGTH) {
            Util.arrayCopyNonAtomic(rpIdBuf, rpIdIdx,
                    outputBuff, outputOff, rpIdLen);
        } else {
            // Truncation necessary...
            short colonPos = -1;
            for (short i = 0; i < rpIdLen; i++) {
                if (rpIdBuf[(short)(rpIdIdx + i)] == (byte) ':') {
                    colonPos = i;
                    break;
                }
            }
            short used = 0;

            if (colonPos != -1) {
                short protocolLen = (short)(colonPos + 1);
                short toCopy = protocolLen <= MAX_RESIDENT_RP_ID_LENGTH ? protocolLen : MAX_RESIDENT_RP_ID_LENGTH;

                Util.arrayCopyNonAtomic(rpIdBuf, rpIdIdx,
                        outputBuff, outputOff, toCopy);

                used += toCopy;
            }

            if ((short)(MAX_RESIDENT_RP_ID_LENGTH - used) < 3) {
                // No room for anything but the protocol bit we already copied
                rpIdLen = used;
            } else {
                // Insert ellipsis
                outputBuff[(short)(outputOff + used++)] = (byte) 0xE2;
                outputBuff[(short)(outputOff + used++)] = (byte) 0x80;
                outputBuff[(short)(outputOff + used++)] = (byte) 0xA6;

                // Copy anything else we have room for after the ellipsis
                short toCopy = (short)(MAX_RESIDENT_RP_ID_LENGTH - used);
                Util.arrayCopyNonAtomic(rpIdBuf, (short)(rpIdIdx + used),
                        outputBuff, (short)(outputOff + used), toCopy);
                rpIdLen = MAX_RESIDENT_RP_ID_LENGTH;
            }
        }

        if (rpIdLen < MAX_RESIDENT_RP_ID_LENGTH) {
            // Zero-fill remainder after RP ID
            Util.arrayFillNonAtomic(outputBuff, (short)(outputOff + rpIdLen),
                    (short)(MAX_RESIDENT_RP_ID_LENGTH - rpIdLen), (byte) 0x00);
        }

        return rpIdLen;
    }

    /**
     * Hand-spun implementation of HMAC-SHA256, to work around lack of hardware support
     *
     * @param apdu Request/response object
     * @param keyBuff Buffer containing 32-byte-long private key
     * @param keyOff Offset of private key in key buffer
     * @param content Buffer containing arbitrary-length content to be HMACed
     * @param contentOff Offset of content in buffer
     * @param contentLen Length of content
     * @param outputBuff Buffer into which output should be written - must have 32 bytes available
     * @param outputOff Write index into output buffer
     */
    private void hmacSha256(APDU apdu, byte[] keyBuff, short keyOff,
                            byte[] content, short contentOff, short contentLen,
                            byte[] outputBuff, short outputOff) {
        final short scratchAmt = (short) ((contentLen < 32 ? 32 : contentLen) + 64);
        short scratchHandle = bufferManager.allocate(apdu, scratchAmt, BufferManager.ANYWHERE);
        byte[] workingBuffer = bufferManager.getBufferForHandle(apdu, scratchHandle);
        short workingFirst = bufferManager.getOffsetForHandle(scratchHandle);
        short workingSecond = (short)(workingFirst + 32);
        short workingMessage = (short)(workingSecond + 32);

        // first half: put key + 32x 0x36 + content into the buffer
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x36)); // ipad
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x36);

        Util.arrayCopyNonAtomic(content, contentOff,
                workingBuffer, workingMessage, contentLen);

        sha256.doFinal(workingBuffer, workingFirst, (short)(64 + contentLen),
                workingBuffer, workingMessage);

        // second half: put key + 32x 0x5c into buffer, then hash into spot adjacent to previous hash
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x5c)); // opad
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x5c);

        sha256.doFinal(workingBuffer, workingFirst, (short) 96, outputBuff, outputOff);

        bufferManager.release(apdu, scratchHandle, scratchAmt);
    }

    /**
     * Uses the currently-set pinToken to hash some data and compare against a verification value
     *
     * @param apdu            Request/response object
     * @param content         Buffer containing content to HMAC using the pinToken
     * @param contentIdx      Index of content in given buffer
     * @param contentLen      Length of content
     * @param checkAgainst    Buffer containing "correct" hash we're looking for
     * @param checkIdx        Index of correct hash in corresponding buffer
     * @param pinProtocol     Integer PIN protocol version number
     * @param invalidateToken If true, consider invalidating the PIN token
     */
    private void checkPinToken(APDU apdu, byte[] content, short contentIdx, short contentLen,
                               byte[] checkAgainst, short checkIdx, byte pinProtocol,
                               boolean invalidateToken) {
        if (pinProtocol != transientStorage.getPinProtocolInUse()) {
            // Can't use PIN protocol 1 with tokens created with v2 or vice versa
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        short checkLength = 16;
        if (pinProtocol == 2) {
            checkLength = 32;
        }

        short scratchHandle = bufferManager.allocate(apdu, (short) 32, BufferManager.ANYWHERE);
        byte[] tempBuf = bufferManager.getBufferForHandle(apdu, scratchHandle);
        short tempOff = bufferManager.getOffsetForHandle(scratchHandle);

        hmacSha256(apdu, pinToken, (short) 0,
                   content, contentIdx, contentLen,
                   tempBuf, tempOff);

        if (Util.arrayCompare(
                tempBuf, tempOff,
                checkAgainst, checkIdx, checkLength
        ) != 0) {
            // PIN token incorrect...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        bufferManager.release(apdu, scratchHandle, (short) 32);

        if (invalidateToken && ONE_USE_PER_PIN_TOKEN) {
            transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
        }
    }

    /**
     * Consumes an incoming pinAuth block and checks it matches our set pinToken.
     *
     * @param apdu                 Request/response object
     * @param buffer               Buffer containing incoming request
     * @param readIdx              Read index into request buffer pointing to a 16-byte array (pinAuth)
     * @param clientDataHashBuffer Buffer containing client data hash
     * @param clientDataHashIdx    Index of the hash of the clientData object, as given by the platform
     * @param pinProtocol          Integer PIN protocol number
     * @param invalidateToken      If true, consider invalidating the PIN token
     */
    private void verifyPinAuth(APDU apdu, byte[] buffer, short readIdx,
                               byte[] clientDataHashBuffer, short clientDataHashIdx,
                               byte pinProtocol, boolean invalidateToken) {
        byte desiredLength = 16;
        if (pinProtocol == 2) {
            desiredLength = 32;
        }

        byte len = buffer[readIdx++];
        if (len == 0x40) {
            if (pinSet) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
            }
        }

        if (desiredLength < 24) {
            if (len != (byte)(0x40 + desiredLength)) { // byte array with included length
                if (len >= (byte) 0x40 && len <= (byte) 0x57) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if (len == 0x58) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else {
            if (len != 0x58) { // byte array, one-byte length
                if (len >= 0x40 && len <= 0x57) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (buffer[readIdx++] != desiredLength) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }

        checkPinToken(apdu, clientDataHashBuffer, clientDataHashIdx, CLIENT_DATA_HASH_LEN,
                buffer, readIdx, pinProtocol, invalidateToken);
    }

    /**
     * Consumes a CBOR block of public key data, and checks if it represents a supported algorithm.
     * After call, transientStorage's idx and len storage will be nonzero if the key is compatible.
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Read index into bufferMem
     * @param lc Length of incoming request, as sent by the platform
     *
     * @return New read index into bufferMem after consuming public key block
     */
    private short checkIfPubKeyBlockSupported(APDU apdu, byte[] buffer, short readIdx, short lc) {
        transientStorage.readyStoredVars();

        byte mapDef = buffer[readIdx++];
        if ((mapDef & 0xF0) != 0xA0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short numMapEntries = (short)(ub(mapDef) - ub((byte) 0xA0));
        if (numMapEntries < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (buffer[readIdx++] != 0x63) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx >= (short)(lc-4)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (buffer[readIdx++] != 'a' || buffer[readIdx++] != 'l' || buffer[readIdx++] != 'g') {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short algIntType = ub(buffer[readIdx++]);
        if (algIntType == 0x0026) { // ES256...
            transientStorage.setStoredVars((short) 1, (byte) 1);
        } else if (algIntType == 0x0038 || algIntType == 0x0018) {
            readIdx++;
        } else if (algIntType == 0x0039 || algIntType == 0x0019) {
            readIdx += 2;
        } else {
            if (!(algIntType >= 0x0020 && algIntType <= 0x0037)
                    && !(algIntType >= 0x0000 && algIntType <= 0x0017)) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        }

        // Skip "type" val
        short typeB = ub(buffer[readIdx]);
        if (typeB < 0x60 || typeB > 0x77) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short valLen = (short)(typeB - 0x60);
        readIdx += valLen + 1;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short typeValB = ub(buffer[readIdx]);
        if (typeValB < 0x60 || typeValB > 0x77) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short typeValLen = (short)(typeValB - 0x60);
        if (typeValLen != CannedCBOR.PUBLIC_KEY_TYPE.length) {
            // not the same length as type "public-key": can't be a match
            transientStorage.readyStoredVars();
        } else if (Util.arrayCompare(buffer, (short)(readIdx + 1),
                CannedCBOR.PUBLIC_KEY_TYPE, (short) 0, typeValLen) != 0) {
            // Not of type "public-key", although same length
            transientStorage.readyStoredVars();
        }
        readIdx += typeValLen + 1;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        for (short i = 2; i < numMapEntries; i++) {
            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
        }

        return readIdx;
    }

    /**
     * Write the portions of an authData block that are used for both makeCredential and getAssertion
     *
     * @param outBuf Buffer into which to write
     * @param adLen Length of the overall AD block
     * @param writeIdx Write index into bufferMem
     * @param flags CTAP2 "flags" byte value
     * @param rpIdBuffer Buffer containing a hash of the RP ID
     * @param rpIdOffset Offset of the RP ID hash in the given buffer
     *
     * @return Additional bytes used for AD basic header beyond the minimum
     */
    private short writeADBasic(byte[] outBuf, short adLen, short writeIdx, byte flags, byte[] rpIdBuffer, short rpIdOffset) {
        short ow = writeIdx;
        writeIdx = encodeIntLenTo(outBuf, writeIdx, adLen, true);

        short adAddlBytes = (short)(writeIdx - ow);

        // RPID hash
        writeIdx = Util.arrayCopyNonAtomic(rpIdBuffer, rpIdOffset, outBuf, writeIdx, RP_HASH_LEN);

        outBuf[writeIdx++] = flags; // flags

        // counter
        encodeCounter(outBuf, writeIdx);

        return adAddlBytes;
    }

    /**
     * Encode signature counter into buffer, also incrementing it by one
     *
     * @param buf Buffer into which to write the counter
     * @param off Offset at which to write counter
     */
    private void encodeCounter(byte[] buf, short off) {
        random.generateData(buf, off, (short) 1);
        boolean ok = counter.increment((short)((buf[off] & 0x0E) + 1));
        if (!ok) {
            throwException(ISO7816.SW_FILE_FULL);
        }
        counter.pack(buf, off);
    }

    /**
     * Writes an authenticated data block into the output buffer.
     *
     * @param outBuf            Buffer into which to write
     * @param writeIdx          Write index into the given output buffer
     * @param adLen             Total length of the AD block
     * @param rpIdHashBuffer    Buffer containing RP ID hash
     * @param rpIdHashOffset    Offset of the RP ID hash in the buffer
     * @param pubKeyBuffer      Buffer containing the PUBLIC key
     * @param pubKeyOffset      Offset of the public key in the corresponding buffer
     * @param flags             Flags byte to pack into authData object
     * @param hmacSecretEnabled true if the HMAC secret extension is in use
     * @param credProtectLevel  Integer (0-3) for level of credProtect enabled; 0 to disable
     * @param uvmRequested      true if the UVM extension is in use
     * @param credBlobState     Positive for successful credBlob; 0 for not requested; -1 for failure
     * @param encodedCredBuffer Buffer containing encoded credential ID
     * @param encodedCredOffset Offset of encoded credential within given buffer
     *
     * @return number of bytes beyond the given adLen which were written to complete the AD block
     */
    private short writeAD(byte[] outBuf,
                          short writeIdx, short adLen, byte[] rpIdHashBuffer, short rpIdHashOffset,
                          byte[] pubKeyBuffer, short pubKeyOffset, byte flags,
                          boolean hmacSecretEnabled, byte credProtectLevel, boolean uvmRequested,
                          boolean minPinRequested, byte credBlobState,
                          byte[] encodedCredBuffer, short encodedCredOffset) {
        short adAddlBytes = writeADBasic(outBuf, adLen, writeIdx, flags, rpIdHashBuffer, rpIdHashOffset);
        writeIdx += getAuthDataLen(false, hmacSecretEnabled, credProtectLevel > 0,
                credBlobState != 0, uvmRequested, minPinRequested, flags) + adAddlBytes;

        // aaguid
        writeIdx = Util.arrayCopyNonAtomic(aaguid, (short) 0, outBuf, writeIdx, (short) aaguid.length);

        // credential ID length
        writeIdx = Util.setShort(outBuf, writeIdx, CREDENTIAL_ID_LEN);

        writeIdx = Util.arrayCopyNonAtomic(encodedCredBuffer, encodedCredOffset,
                outBuf, writeIdx, CREDENTIAL_ID_LEN);

        // Public key
        writeIdx = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE, (short) 0,
                outBuf, writeIdx, (short) CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE.length);
        writeIdx = writePubKey(outBuf, writeIdx, pubKeyBuffer, pubKeyOffset);

        short numExtensions = 0;
        if (hmacSecretEnabled) {
            numExtensions++;
        }
        if (credProtectLevel > 0) {
            numExtensions++;
        }
        if (credBlobState != 0) {
            numExtensions++;
        }
        if (uvmRequested) {
            numExtensions++;
        }
        if (minPinRequested) {
            numExtensions++;
        }

        if (numExtensions > 0) {
            outBuf[writeIdx++] = (byte)(0xA0 + numExtensions);
        }

        if (uvmRequested) {
            writeIdx = writeUVM(outBuf, writeIdx, flags);
        }

        if (credBlobState != 0) {
            writeIdx = encodeIntLenTo(outBuf, writeIdx, (byte) CannedCBOR.CRED_BLOB_EXTENSION_ID.length, false);
            writeIdx = Util.arrayCopy(CannedCBOR.CRED_BLOB_EXTENSION_ID, (short) 0,
                    outBuf, writeIdx, (short) CannedCBOR.CRED_BLOB_EXTENSION_ID.length);
            outBuf[writeIdx++] = (byte)(credBlobState == -1 ? 0xF4 : 0xF5);
        }

        if (credProtectLevel > 0) {
            writeIdx = encodeIntLenTo(outBuf, writeIdx, (byte) CannedCBOR.CRED_PROTECT_EXTENSION_ID.length, false);
            writeIdx = Util.arrayCopy(CannedCBOR.CRED_PROTECT_EXTENSION_ID, (short) 0,
                    outBuf, writeIdx, (short) CannedCBOR.CRED_PROTECT_EXTENSION_ID.length);
            outBuf[writeIdx++] = credProtectLevel;
        }

        if (hmacSecretEnabled) {
            writeIdx = encodeIntLenTo(outBuf, writeIdx, (byte) CannedCBOR.HMAC_SECRET_EXTENSION_ID.length, false);
            writeIdx = Util.arrayCopy(CannedCBOR.HMAC_SECRET_EXTENSION_ID, (short) 0,
                    outBuf, writeIdx, (short) CannedCBOR.HMAC_SECRET_EXTENSION_ID.length);
            outBuf[writeIdx++] = (byte) 0xF5; // boolean true
        }

        if (minPinRequested) {
            writeIdx = encodeIntLenTo(outBuf, writeIdx, (byte) CannedCBOR.MIN_PIN_LENGTH.length, false);
            writeIdx = Util.arrayCopy(CannedCBOR.MIN_PIN_LENGTH, (short) 0,
                    outBuf, writeIdx, (short) CannedCBOR.MIN_PIN_LENGTH.length);
            if (minPinLength > 23) {
                outBuf[writeIdx++] = 0x18; // one-byte integer
            }
            outBuf[writeIdx++] = minPinLength;
        }

        return adAddlBytes;
    }

    /**
     * Writes UVM extension output to the buffer
     *
     * @param outBuf Buffer into which to write
     * @param writeIdx Index into output buffer to start writing
     * @param flags Flags byte indicating UP/UV, etc
     * @return New index into output buffer
     */
    private short writeUVM(byte[] outBuf, short writeIdx, byte flags) {
        writeIdx = encodeIntLenTo(outBuf, writeIdx, (byte) CannedCBOR.UVM_EXTENSION_ID.length, false);
        writeIdx = Util.arrayCopy(CannedCBOR.UVM_EXTENSION_ID, (short) 0,
                outBuf, writeIdx, (short) CannedCBOR.UVM_EXTENSION_ID.length);
        boolean userVerified = (flags & 0x04) != 0;
        outBuf[writeIdx++] = (byte) 0x81; // one "factor": one-element array
        outBuf[writeIdx++] = (byte) 0x83; // three-element array
        if (userVerified) {
            outBuf[writeIdx++] = 0x19; // two-byte integer
            writeIdx = Util.setShort(outBuf, writeIdx, (short) 0x0800); // user verification method passcode_external
        } else {
            outBuf[writeIdx++] = 0x01; // user verification method presence
        }
        outBuf[writeIdx++] = 0x0A; // key protection type secure element + hardware
        outBuf[writeIdx++] = 0x04; // matcher protection type on-chip
        return writeIdx;
    }

    /**
     * Builds a credential ID into a given buffer
     *
     * @param apdu Request/response object
     * @param privKey Private key to pack into credentialID
     * @param rpIdHashBuffer Buffer containing hash of RP ID
     * @param rpIdHashOffset Index of RP ID hash in corresponding buffer
     * @param outBuffer Buffer into which to write the encoded credential - must have CREDENTIAL_ID_LEN bytes available
     * @param outOffset Offset at which to encode the credential ID into the output buffer
     * @param rkNum New index in RK store if the credential is going to be a discoverable one; -1 otherwise
     * @param lowSecurity true if the credential is allowed to be encoded with the low-security wrapping key
     * @param credProtectLevel The credProtect extension protection level to store inside the credential
     * @return true if the credential was encrypted "low security", false if "high security"
     */
    private boolean encodeCredentialID(APDU apdu, ECPrivateKey privKey,
                                       byte[] rpIdHashBuffer, short rpIdHashOffset,
                                       byte[] outBuffer, short outOffset,
                                       short rkNum, boolean lowSecurity, byte credProtectLevel) {
        if (rkNum >= 0 && !USE_LOW_SECURITY_FOR_SOME_RKS) {
            lowSecurity = false;
        }
        // use low security even for RKs if LOW_SECURITY_MAXIMUM_COMPLIANCE
        if (LOW_SECURITY_MAXIMUM_COMPLIANCE) {
            lowSecurity = true;
        }
        // regardless of anything else, opportunistically use the high-sec key for credProtect-level-3 creds
        final byte pinProtocolInUse = transientStorage.getPinProtocolInUse();
        if (credProtectLevel == 3 && (pinProtocolInUse == 1 || pinProtocolInUse == 2)) {
            lowSecurity = false;
        }
        AESKey key = lowSecurity ? lowSecurityWrappingKey : highSecurityWrappingKey;

        if (!lowSecurity && pinSet && transientStorage.getPinProtocolInUse() == 0) {
            // We're trying to make a new high-security credential, but the PIN isn't available!
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        final short scratchHandle = bufferManager.allocate(apdu, KEY_POINT_LENGTH, BufferManager.ANYWHERE);
        final byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);

        privKey.getS(scratch, scratchOff);

        // Generate random IV for new credential
        random.generateData(outBuffer, outOffset, IV_LEN);
        short payloadOffset = (short) (outOffset + IV_LEN);

        payloadOffset = Util.arrayCopyNonAtomic(rpIdHashBuffer, rpIdHashOffset,
                outBuffer, payloadOffset, RP_HASH_LEN);
        payloadOffset = Util.arrayCopyNonAtomic(scratch, scratchOff,
                outBuffer, payloadOffset, KEY_POINT_LENGTH);

        outBuffer[payloadOffset++] = (byte)(rkNum >= 0 ? (0x80 | credProtectLevel) : credProtectLevel);
        random.generateData(outBuffer, payloadOffset, (short) 15);
        payloadOffset += 15;

        symmetricWrapper.init(key, Cipher.MODE_ENCRYPT,
                outBuffer, outOffset, IV_LEN);
        final short encryptedBytes = symmetricWrapper.doFinal(outBuffer, (short)(outOffset + IV_LEN), CREDENTIAL_PAYLOAD_LEN,
                outBuffer, (short)(outOffset + IV_LEN));

        hmacSha256(apdu, credentialVerificationKey, (short) 0,
                outBuffer, outOffset, (short)(CREDENTIAL_PAYLOAD_LEN + IV_LEN - 14),
                scratch, scratchOff);
        Util.arrayCopyNonAtomic(scratch, scratchOff,
                outBuffer, payloadOffset, (short) 16);

        bufferManager.release(apdu, scratchHandle, KEY_POINT_LENGTH);

        if (encryptedBytes != CREDENTIAL_PAYLOAD_LEN) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }

        return lowSecurity;
    }

    /**
     * Pack an EC public key into the given buffer
     *
     * @param outBuf Buffer into which to write
     * @param outputLen The current index in the output buffer (begin writing here)
     * @param pubKeyBuffer A buffer containing the public key to be written in the format X || Y
     * @param pubKeyOffset An index pointing to the X-coordinate of the public key
     *
     * @return New index in the output buffer after writes
     */
    private short writePubKey(byte[] outBuf, short outputLen, byte[] pubKeyBuffer, short pubKeyOffset) {
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, pubKeyOffset,
                outBuf, outputLen, KEY_POINT_LENGTH);
        outBuf[outputLen++] = 0x22; // map key: y-coordinate
        outBuf[outputLen++] = 0x58; // byte string with one-byte length to follow
        outBuf[outputLen++] = (byte) KEY_POINT_LENGTH;
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, (short) (pubKeyOffset + KEY_POINT_LENGTH),
                outBuf, outputLen, KEY_POINT_LENGTH);
        return outputLen;
    }

    /**
     * Calculates the length of an auth data segment
     *
     * @param includeAttestedKey If true, includes attestion data - for makeCredential
     * @param useHmacSecret If true, includes the bytes for the hmac-secret extension
     * @param useCredProtect If true, includes the bytes for the credProtect extension
     * @param useCredBlob If true, includes the bytes for the credBlob extension
     * @param useUVM If true, includes the bytes for the UVM extension
     * @param useMinPin If true, includes the bytes for the minPinLength extension
     * @param flags The flags byte applied to the response
     *
     * @return The number of bytes in the authentication data segment
     */
    private short getAuthDataLen(boolean includeAttestedKey, boolean useHmacSecret, boolean useCredProtect,
                                 boolean useCredBlob, boolean useUVM, boolean useMinPin, byte flags) {
        short basicLen = (short) (RP_HASH_LEN + // RP ID hash
                1 + // flags byte
                4 // counter
        );

        if (!includeAttestedKey) {
            return basicLen;
        }

        final byte minPinExtBytes = (byte)(minPinLength > 23 ? 4 : 3);
        final byte uvmExtBytes = (byte)((flags & 0x04) != 0 ? 9 : 7);

        return (short) (basicLen +
                (short) aaguid.length + // aaguid
                2 + // credential ID length
                CREDENTIAL_ID_LEN + // credential ID
                CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE.length + // preamble for cred public key
                KEY_POINT_LENGTH + // x-point
                3 + // CBOR bytes to introduce the y-point
                KEY_POINT_LENGTH + // y-point
                (useCredProtect || useHmacSecret || useCredBlob ? 1 : 0) + // extension data intro
                (useHmacSecret ? 2 + CannedCBOR.HMAC_SECRET_EXTENSION_ID.length : 0) + // extension data
                (useCredProtect ? 2 + CannedCBOR.CRED_PROTECT_EXTENSION_ID.length : 0) + // more extension data
                (useCredBlob ? 2 + CannedCBOR.CRED_BLOB_EXTENSION_ID.length : 0) + // yet more extension data
                (useUVM ? uvmExtBytes + CannedCBOR.UVM_EXTENSION_ID.length : 0) + // why is there still more extension data
                (useMinPin ? minPinExtBytes + CannedCBOR.MIN_PIN_LENGTH.length : 0) // I hope we're done with extensions now
        );
    }

    /**
     * Handles a CTAP2 getAssertion or getNextAssertion API call.
     * Note that this method is called a second time for getNextAssertion, so it needs to preserve (and restore) state
     * in scratch.
     *
     * @param apdu The request/response object
     * @param lc The declared request length
     * @param buffer Buffer containing input request
     * @param firstCredIdx The first credential to consider in resident key storage
     */
    private void getAssertion(final APDU apdu, final short lc, final byte[] buffer,
                              final short firstCredIdx) {
        short readIdx = 1;


        // These allocations might need to persist until next time, when we get a GetNextAssertion call
        // If we ARE a getNextAssertion call, we're just re-getting their indices into existing storage...
        final byte startingAllowedMemory = BufferManager.NOT_APDU_BUFFER;
        short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, startingAllowedMemory);
        byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        short scratchRPIDHashIdx = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, startingAllowedMemory);
        byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        short clientDataHashIdx = bufferManager.getOffsetForHandle(clientDataHashHandle);
        // first byte, PIN protocol. Second byte a bitfield:
        // 1 for PIN auth success, 2 for credBlob requested, 3 for LBK requested, 4 for UVM requested
        short stateKeepingHandle = bufferManager.allocate(apdu, (short) 2, startingAllowedMemory);
        byte[] stateKeepingBuffer = bufferManager.getBufferForHandle(apdu, stateKeepingHandle);
        short stateKeepingIdx = bufferManager.getOffsetForHandle(stateKeepingHandle);
        // first byte length, remaining bytes HMAC salt
        short hmacSaltHandle = bufferManager.allocate(apdu, (short) 65, startingAllowedMemory);
        byte[] hmacSaltBuffer = bufferManager.getBufferForHandle(apdu, hmacSaltHandle);
        short hmacSaltIdx = bufferManager.getOffsetForHandle(hmacSaltHandle);

        final short credStorageHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, startingAllowedMemory);
        final short credStorageOffset = bufferManager.getOffsetForHandle(credStorageHandle);
        final byte[] credStorageBuffer = bufferManager.getBufferForHandle(apdu, credStorageHandle);

        boolean acceptedMatch = false;

        short hmacSecretBytes = 0;
        byte numMatchesThisRP = 0;
        short rkMatch = -1;
        short allowListLength = 0;

        if (resetRequested) {
            resetRequested = false;
        }

        if (firstCredIdx == 0) { // Start of iteration: actually parse request
            stateKeepingBuffer[stateKeepingIdx] = 1; // default to PIN protocol one
            stateKeepingBuffer[(short)(stateKeepingIdx + 1)] = 0;

            if (lc == 0) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }

            if ((buffer[readIdx] & 0xF0) != 0xA0) { // map with relatively few entries
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            final short numParams = getMapEntryCount(apdu, buffer[readIdx++]);
            if (numParams < 2) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (readIdx >= (short)(lc - 32)) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            if (buffer[readIdx++] != 0x01) { // rpId
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }

            short rpIdLen;
            if (buffer[readIdx] == 0x78) { // one-byte length
                readIdx++;
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                rpIdLen = buffer[readIdx++];
            } else if (buffer[readIdx] >= 0x61 && buffer[readIdx] < 0x78) { // zero-byte packed length
                rpIdLen = (short) (buffer[readIdx] - 0x60);
                readIdx++;
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                return; // unreachable, but the JVM doesn't know that
            }
            final short rpIdIdx = readIdx;
            readIdx += rpIdLen;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            if (buffer[readIdx++] != 0x02) { // clientDataHash
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            short clientDataHashLen = -1;
            if (buffer[readIdx++] == 0x58) {
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                clientDataHashLen = buffer[readIdx++];
            }
            if (clientDataHashLen != CLIENT_DATA_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }
            Util.arrayCopyNonAtomic(buffer, readIdx,
                    clientDataHashBuffer, clientDataHashIdx, CLIENT_DATA_HASH_LEN);
            readIdx += CLIENT_DATA_HASH_LEN;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashIdx);

            short allowListIdx = -1;

            short paramsRead = 2;
            if (numParams > 2 && buffer[readIdx] == 0x03) { // allowList
                readIdx++;
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }

                // We need to defer this until after we do PIN processing
                allowListIdx = readIdx;
                paramsRead++;
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }

            defaultOptions();
            short pinAuthIdx = -1;
            short hmacSecretReadIdx = -1;

            // Consume any remaining parameters
            byte lastMapKey = 0x03; // Doesn't matter if it's actually 0x02 or whatever, we just need them in order
            for (short i = paramsRead; i < numParams; i++) {
                byte mapKey = buffer[readIdx++];
                if (mapKey <= lastMapKey) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                lastMapKey = mapKey;
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }

                short mapEntries, keyLength, j;
                switch (mapKey) {
                    case 0x04: // extensions
                        mapEntries = getMapEntryCount(apdu, buffer[readIdx++]);
                        for (j = 0; j < mapEntries; j++) {
                            if ((buffer[readIdx] & 0x60) != 0x60) {
                                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                            }
                            keyLength = (short) (buffer[readIdx++] & 0x0F);

                            if (keyLength == CannedCBOR.CRED_BLOB_EXTENSION_ID.length && Util.arrayCompare(buffer, readIdx,
                                    CannedCBOR.CRED_BLOB_EXTENSION_ID, (short) 0, (short) CannedCBOR.CRED_BLOB_EXTENSION_ID.length) == 0) {
                                // credBlob extension
                                readIdx += keyLength;
                                byte valueByte = buffer[readIdx++];
                                if (valueByte == (byte) 0xF5) { // true
                                    stateKeepingBuffer[(short)(stateKeepingIdx + 1)] |= 0x02;
                                } else if (valueByte == (byte) 0xF4) { // false
                                    // nothing to do here: they explicitly DIDN'T ask for the credBlob...
                                } else { // wat
                                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                                }
                                continue;
                            } else if (keyLength == CannedCBOR.LARGE_BLOB_EXTENSION_ID.length && Util.arrayCompare(buffer, readIdx,
                                    CannedCBOR.LARGE_BLOB_EXTENSION_ID, (short) 0, (short) CannedCBOR.LARGE_BLOB_EXTENSION_ID.length) == 0) {
                                // largeBlobKey extension
                                readIdx += keyLength;
                                byte valueByte = buffer[readIdx++];
                                if (valueByte == (byte) 0xF5) { // true
                                    stateKeepingBuffer[(short)(stateKeepingIdx + 1)] |= 0x04;
                                } else if (valueByte == (byte) 0xF4) {
                                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                                } else {
                                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                                }
                                continue;
                            } else if (keyLength == CannedCBOR.UVM_EXTENSION_ID.length && Util.arrayCompare(buffer, readIdx,
                                    CannedCBOR.UVM_EXTENSION_ID, (short) 0, (short) CannedCBOR.UVM_EXTENSION_ID.length) == 0) {
                                // uvm extension
                                readIdx += keyLength;
                                byte valueByte = buffer[readIdx++];
                                if (valueByte == (byte) 0xF5) { // true
                                    stateKeepingBuffer[(short)(stateKeepingIdx + 1)] |= 0x08;
                                } else if (valueByte == (byte) 0xF4) { // false
                                    // nothing to do here: they explicitly DIDN'T ask for UVM...
                                } else { // ah yes, the OTHER uvm option
                                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                                }
                                continue;
                            } else if (keyLength != CannedCBOR.HMAC_SECRET_EXTENSION_ID.length || Util.arrayCompare(buffer, readIdx,
                                    CannedCBOR.HMAC_SECRET_EXTENSION_ID, (short) 0, (short) CannedCBOR.HMAC_SECRET_EXTENSION_ID.length) != 0) {
                                // Unsupported extension: ignore it
                                readIdx = consumeAnyEntity(apdu, buffer, (short) (readIdx + keyLength), lc);
                                continue;
                            }

                            readIdx += keyLength;

                            // We've got a case of hmac-secret extension params!
                            // store the index and revisit it later, when we've handled the PIN protocol
                            hmacSecretReadIdx = readIdx;
                            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                        }

                        break;
                    case 0x05: // options
                        readIdx = processOptionsMap(apdu, buffer, readIdx, lc, false, false);
                        break;
                    case 0x06: // pinAuth
                        pinAuthIdx = readIdx;
                        // Read past this and come back later, when pinProtocol is set correctly
                        readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                        break;
                    case 0x07: // pinProtocol
                        stateKeepingBuffer[stateKeepingIdx] = buffer[readIdx++];
                        checkPinProtocolSupported(apdu, stateKeepingBuffer[stateKeepingIdx]);
                        break;
                    default:
                        readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                        break;
                }
            }

            if (hmacSecretReadIdx != -1) {
                // Check validity of HMAC salt parameters before we validate the PIN
                // The FIDO compliance tests require this even though it's a waste of time :-(
                extractHMACSalt(apdu, buffer, hmacSecretReadIdx, lc,
                        null, (short) 0, true);
            }

            boolean pinProvided = pinAuthIdx != -1;
            byte pinProtocol = transientStorage.getPinProtocolInUse();

            if (!pinProvided) {
                if (alwaysUv) {
                    // When alwaysUv is set, we must have a PIN!
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
                }
            } else {
                if (buffer[pinAuthIdx] == 0x40) {
                    // For CTAP2.0 compatibility: just checking which authenticator to use
                    if (pinSet) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
                    }
                }

                // check the provided PIN
                final byte pinPermissions = transientStorage.getPinPermissions();
                final boolean shouldInvalidatePinToken = transientStorage.hasUPOption();

                verifyPinAuth(apdu, buffer, pinAuthIdx, clientDataHashBuffer, clientDataHashIdx,
                        stateKeepingBuffer[stateKeepingIdx], shouldInvalidatePinToken);

                if ((pinPermissions & FIDOConstants.PERM_GET_ASSERTION) == 0) {
                    // PIN token doesn't have permission for the GA operation
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }

                if (WRITES_INVALIDATE_PINS && shouldInvalidatePinToken) {
                    transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
                }

                stateKeepingBuffer[(short)(stateKeepingIdx + 1)] |= 0x01;
            }

            if (pinSet && pinProvided && transientStorage.hasUVOption()) {
                // When a PIN is set and provided, the "uv" input option MUST NOT be set.
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
            }

            // Report PIN-validation failures before we report lack of matching creds
            if (pinSet && pinProvided) {
                if (pinProtocol != stateKeepingBuffer[stateKeepingIdx]) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }

            if (pinProvided) {
                if (permissionsRpId[0] == 0x00) {
                    // getting an assertion with a PIN token created with default perms binds it to this RP ID
                    permissionsRpId[0] = 0x01;
                    Util.arrayCopyNonAtomic(scratchRPIDHashBuffer, scratchRPIDHashIdx,
                            permissionsRpId, (short) 1, RP_HASH_LEN);
                } else {
                    // Permissions RP ID is set - check it
                    if (Util.arrayCompare(scratchRPIDHashBuffer, scratchRPIDHashIdx,
                            permissionsRpId, (short) 1, RP_HASH_LEN) != 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }
            }

            loadWrappingKeyIfNoPIN();

            if (allowListIdx != -1) {
                short blockReadIdx = allowListIdx;
                allowListLength = ub(buffer[blockReadIdx++]);
                if (allowListLength < 0x0080 || allowListLength > 0x0097) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                allowListLength -= 0x0080;
                if (blockReadIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }

                for (short i = 0; i < allowListLength; i++) {
                    blockReadIdx = consumeMapAndGetID(apdu, buffer, blockReadIdx, lc, true, true, false, false);

                    if (acceptedMatch) {
                        // In CTAP2.1, we are done, as we're supposed to treat the match we already made as the only match
                        // we're just continuing iteration to throw exceptions when we encounter invalid allowList entries
                        // AFTER the valid one
                        continue;
                    }

                    final short credIdx = transientStorage.getStoredIdx();
                    final short credLen = transientStorage.getStoredLen();

                    if (credLen != CREDENTIAL_ID_LEN) {
                        // Invalid allow list entry - ignore
                        continue;
                    }

                    // The FIDO compliance tests check that deleting a resident credential also makes
                    // attempts to use it via the allowList fail. So we'll run through our stored keys and validate
                    // that we have something matching this before we accept it
                    rkMatch = scanRKsForExactCredential(buffer, credIdx);

                    if (checkCredential(apdu, buffer, credIdx, credLen, scratchRPIDHashBuffer, scratchRPIDHashIdx,
                            credStorageBuffer, credStorageOffset, rkMatch, (byte)(pinProvided ? 3 : 2))) {
                        // valid credential
                        acceptedMatch = true;

                        numMatchesThisRP++;

                        // First load the decrypted private key, then overwrite with the public credential
                        loadScratchIntoAttester(credStorageBuffer, (short)(credStorageOffset + RP_HASH_LEN));
                        Util.arrayCopyNonAtomic(buffer, credIdx,
                                credStorageBuffer, credStorageOffset, credLen);
                    }
                }
            }

            if (hmacSecretReadIdx != -1) {
                // Come back and load HMAC salts into scratch space
                hmacSaltBuffer[hmacSaltIdx] = extractHMACSalt(apdu, buffer, hmacSecretReadIdx, lc,
                        hmacSaltBuffer, (short)(hmacSaltIdx + 1), false);
            } else {
                hmacSaltBuffer[hmacSaltIdx] = 0;
            }
        }

        byte potentialAssertionIterationPointer = 0;

        if (allowListLength == 0 && numResidentCredentials > 0) {
            // Scan resident keys for match

            short credTempHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.ANYWHERE);
            short credTempOffset = bufferManager.getOffsetForHandle(credTempHandle);
            byte[] credTempBuffer = bufferManager.getBufferForHandle(apdu, credTempHandle);

            final boolean pinAuthPerformed = (stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x01) != 0;

            final short firstCred = firstCredIdx == 0 ? (short)(numResidentCredentials - 1) : (short)(firstCredIdx - 2);
            for (short i = firstCred; i >= 0; i--) {
                if (checkCredential(apdu, i, scratchRPIDHashBuffer, scratchRPIDHashIdx,
                        credTempBuffer, credTempOffset, (byte)(pinAuthPerformed ? 3 : 1))) {
                    // Got a resident key hit!

                    numMatchesThisRP++;

                    if (rkMatch == -1) {
                        rkMatch = i;
                        potentialAssertionIterationPointer = (byte) (i + 1);
                        loadScratchIntoAttester(credTempBuffer, (short)(credTempOffset + RP_HASH_LEN));

                        Util.arrayCopyNonAtomic(residentKeys[i].getEncryptedCredentialID(), (short) 0,
                                credStorageBuffer, credStorageOffset, residentKeys[i].getCredLen());
                        acceptedMatch = true;

                        // Continue iterating so we're constant-time
                    }
                }
            }

            bufferManager.release(apdu, credTempHandle, CREDENTIAL_PAYLOAD_LEN);
        }

        if (!acceptedMatch) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        final byte memPositioning = BufferManager.NOT_APDU_BUFFER;

        final short hmacOutputHandle = bufferManager.allocate(apdu, (short) 80, memPositioning);
        final short hmacOutputOffset = bufferManager.getOffsetForHandle(hmacOutputHandle);
        final byte[] hmacOutputBuffer = bufferManager.getBufferForHandle(apdu, hmacOutputHandle);

        if (hmacSaltBuffer[hmacSaltIdx] != 0) {
            final byte hmacSaltLen = (byte)(hmacSaltBuffer[hmacSaltIdx] & 0xFC);
            final byte hmacSaltPinProtocol = (byte)(hmacSaltBuffer[hmacSaltIdx] & 0x03);
            hmacSecretBytes = computeHMACSecret(apdu, (ECPrivateKey) ecKeyPair.getPrivate(),
                    hmacSaltBuffer, (short)(hmacSaltIdx + 1), hmacSaltLen,
                    hmacSaltPinProtocol, hmacOutputBuffer, hmacOutputOffset,
                    (stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x01) != 0
            );
        }

        // RESPONSE BELOW HERE
        byte[] outputBuffer = bufferMem;
        short outputIdx = (short) 0;

        outputBuffer[outputIdx++] = FIDOConstants.CTAP2_OK;

        boolean providingLBK = rkMatch > -1 && (stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x04) != 0;
        boolean providingUVM = (stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x08) != 0;
        boolean providingCredBlob = (stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x02) != 0;
        byte numMapEntries = 3;
        if (rkMatch > -1) {
            numMapEntries++; // user block
        }
        if (firstCredIdx == 0 && numMatchesThisRP > 1) {
            numMapEntries++; // numberOfCredentials
        }
        if (providingLBK) {
            numMapEntries++; // largeBlobKey
        }

        outputBuffer[outputIdx++] = (byte) (0xA0 + numMapEntries); // map with some entry count
        outputBuffer[outputIdx++] = 0x01; // map key: credential

        // credential
        outputIdx = packCredentialId(credStorageBuffer, credStorageOffset,
                outputBuffer, outputIdx);

        outputBuffer[outputIdx++] = 0x02; // map key: authData

        byte flags = transientStorage.hasUPOption() ? (byte) 0x01 : 0x00;
        if ((stateKeepingBuffer[(short)(stateKeepingIdx + 1)] & 0x01) != 0) {
            // UV flag bit
            flags = (byte)(flags | 0x04);
        }

        short adLen = getAuthDataLen(false, false,
                false, false, false, false, flags);
        short extensionDataLen = 0;
        byte numExtensions = 0;
        short credBlobBytes = 0;
        if (hmacSecretBytes > 0 || providingUVM || providingCredBlob) {
            flags = (byte)(flags | 0x80); // extension data bit
            extensionDataLen += 1;
            if (hmacSecretBytes > 0) {
                extensionDataLen += (short) (
                        hmacSecretBytes +
                                3 + // CBOR overhead bytes
                                CannedCBOR.HMAC_SECRET_EXTENSION_ID.length
                );
                numExtensions++;
            }
            if (providingCredBlob) {
                if (rkMatch != -1) {
                    credBlobBytes = residentKeys[rkMatch].getCredBlobLen();
                }
                short overheadBytes = 2;
                if (credBlobBytes > 23) {
                    overheadBytes++;
                }
                extensionDataLen += (short) (
                        credBlobBytes +
                                overheadBytes +
                                CannedCBOR.CRED_BLOB_EXTENSION_ID.length
                );
                numExtensions++;
            }
            if (providingUVM) {
                short uvmBytes = 6;
                if ((flags & 0x04) != 0) {
                    uvmBytes += 2;
                }
                extensionDataLen += (short) (
                        uvmBytes + CannedCBOR.UVM_EXTENSION_ID.length
                );
                numExtensions++;
            }
        }

        // authData (no attestation...)
        final short adAddlBytes = writeADBasic(outputBuffer, (short) (adLen + extensionDataLen), outputIdx, flags,
                scratchRPIDHashBuffer, scratchRPIDHashIdx);

        final short startOfAD = (short) (outputIdx + adAddlBytes);

        outputIdx = (short) (startOfAD + adLen);
        final short beforeExtensionOutputLen = outputIdx;
        if (numExtensions > 0) {
            outputBuffer[outputIdx++] = (byte) (0xA0 + numExtensions); // map with some small number of items
        }
        if (providingUVM) {
            outputIdx = writeUVM(outputBuffer, outputIdx, flags);
        }
        if (providingCredBlob) {
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, (byte) CannedCBOR.CRED_BLOB_EXTENSION_ID.length, false);
            outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.CRED_BLOB_EXTENSION_ID, (short) 0,
                    outputBuffer, outputIdx, (short) CannedCBOR.CRED_BLOB_EXTENSION_ID.length);
            if (credBlobBytes == 0) {
                outputBuffer[outputIdx++] = 0x40; // empty byte array
            } else {
                short credBlobLen = residentKeys[rkMatch].getCredBlobLen();
                outputIdx = encodeIntLenTo(outputBuffer, outputIdx, credBlobLen, true);
                // We're done with the HMAC salt, so we can reuse that buffer to hold the credBlob
                residentKeys[rkMatch].unpackCredBlob(getAESKeyForExistingRK(rkMatch), symmetricUnwrapper,
                        hmacSaltBuffer, (short)(hmacSaltIdx + 1));
                outputIdx = Util.arrayCopyNonAtomic(hmacSaltBuffer, (short)(hmacSaltIdx + 1),
                        outputBuffer, outputIdx, credBlobBytes);
            }
        }
        if (hmacSecretBytes > 0) {
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, (byte) CannedCBOR.HMAC_SECRET_EXTENSION_ID.length, false);
            outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.HMAC_SECRET_EXTENSION_ID, (short) 0,
                    outputBuffer, outputIdx, (short) CannedCBOR.HMAC_SECRET_EXTENSION_ID.length);
            outputBuffer[outputIdx++] = 0x58; // byte string: one-byte length
            outputBuffer[outputIdx++] = (byte) hmacSecretBytes;
            outputIdx = Util.arrayCopyNonAtomic(hmacOutputBuffer, hmacOutputOffset,
                    outputBuffer, outputIdx, hmacSecretBytes);
        }
        if ((short)(outputIdx - beforeExtensionOutputLen) != extensionDataLen) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
        }

        bufferManager.release(apdu, hmacOutputHandle, (short) 80);

        // TEMPORARILY copy the clientDataHash into the output buffer so we have a contiguous signing block
        // We'll overwrite it again in a moment, so don't advance the output write index
        Util.arrayCopyNonAtomic(clientDataHashBuffer, clientDataHashIdx,
                outputBuffer, outputIdx, CLIENT_DATA_HASH_LEN);
        final short sigLength = attester.sign(outputBuffer, startOfAD, (short)(adLen + extensionDataLen + CLIENT_DATA_HASH_LEN),
                outputBuffer, (short)(outputIdx + 3)); // 3 byte space: map key, byte array type, byte array length

        // advance past the signature we just wrote, which overwrote the clientDataHash in the buffer
        outputBuffer[outputIdx++] = 0x03; // map key: signature

        if (sigLength < 24) {
            // Short signature: move in one byte
            Util.arrayCopyNonAtomic(outputBuffer, (short)(outputIdx + 2),
                    outputBuffer, (short)(outputIdx + 1), sigLength);
        } else if (sigLength > 255) {
            // Long signature: move out one byte
            Util.arrayCopyNonAtomic(outputBuffer, (short)(outputIdx + 2),
                    outputBuffer, (short)(outputIdx + 3), sigLength);
        }

        outputIdx = encodeIntLenTo(outputBuffer, outputIdx, sigLength, true);
        outputIdx += sigLength;

        if (rkMatch > -1) {
            final short uidLen = residentKeys[rkMatch].getUserIdLength();
            final boolean returningUserName = (flags & 0x04) != 0;

            outputBuffer[outputIdx++] = 0x04; // map key: user
            if (returningUserName) {
                outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.ID_AND_NAME_MAP_PREAMBLE, (short) 0,
                        outputBuffer, outputIdx, (short) CannedCBOR.ID_AND_NAME_MAP_PREAMBLE.length);
            } else {
                outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.SINGLE_ID_MAP_PREAMBLE, (short) 0,
                        outputBuffer, outputIdx, (short) CannedCBOR.SINGLE_ID_MAP_PREAMBLE.length);
            }
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, uidLen, true);
            // Pack the user ID from the resident key into the buffer, after decrypting it
            residentKeys[rkMatch].unpackUserID(getAESKeyForExistingRK(rkMatch), symmetricUnwrapper,
                    outputBuffer, outputIdx);
            outputIdx += uidLen; // only advance by the ACTUAL length of the UID, not the padded size

            if (returningUserName) {
                final short nameLength = residentKeys[rkMatch].getUserNameLength();
                outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.NAME, (short) 0,
                        outputBuffer, outputIdx, (short) CannedCBOR.NAME.length);
                outputIdx = encodeIntLenTo(outputBuffer, outputIdx, nameLength, false);
                residentKeys[rkMatch].unpackUserName(getAESKeyForExistingRK(rkMatch), symmetricUnwrapper,
                        outputBuffer, outputIdx);
                outputIdx += nameLength;
            }
        }

        if (firstCredIdx == 0 && numMatchesThisRP > 1) {
            outputBuffer[outputIdx++] = 0x05; // map key: numberOfCredentials
            outputIdx = encodeIntTo(outputBuffer, outputIdx, numMatchesThisRP);
        }

        if (providingLBK) {
            outputBuffer[outputIdx++] = 0x07; // map key: largeBlobKey
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, (byte) 32, true);
            residentKeys[rkMatch].emitLargeBlobKey(
                    getAESKeyForExistingRK(rkMatch), symmetricWrapper,
                    outputBuffer, outputIdx);
            outputIdx += 32;
        }

        // After this write, we are done with the credential private key we loaded.
        // It might be stored in flash, so let's clear that out.
        ecKeyPair.getPrivate().clearKey();

        transientStorage.setAssertIterationPointer(potentialAssertionIterationPointer);

        // We didn't write our output to the APDU buffer, so it must be copied there - in whole or in part
        doSendResponse(apdu, outputIdx);
    }

    /**
     * Checks if a particular credential ID (as a byte string) is present and valid in our RK set
     *
     * @param buffer Buffer containing encoded credential ID
     * @param credIdx Index of credential ID in input buffer
     *
     * @return index of RK if credential is present, valid, and its level usable with the
     *         amount of PIN auth performed; negative number otherwise
     */
    private short scanRKsForExactCredential(byte[] buffer, short credIdx) {
        for (short i = 0; i < (short) residentKeys.length; i++) {
            if (residentKeys[i] == null) {
                break;
            }

            // Byte comparison will suffice, no need to decrypt the RK
            if (Util.arrayCompare(buffer, credIdx,
                    residentKeys[i].getEncryptedCredentialID(), (short) 0, residentKeys[i].getCredLen()) == 0) {
                // Match! This credential is still valid in our RK list
                return i;
            }
        }

        return -1;
    }

    /**
     * Sends an error to the client if the given PIN protocol version is not supported
     *
     * @param apdu Request/response object
     * @param pinProtocol Integer PIN protocol version number
     */
    private void checkPinProtocolSupported(APDU apdu, byte pinProtocol) {
        if (pinProtocol != 1 && pinProtocol != 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }
    }

    /**
     * Initializes the attester with a given key. After call, attestations may be made.
     *
     * @param buffer Buffer containing 32 bytes of key data
     * @param offset Offset into given buffer of key's first byte
     */
    private void loadScratchIntoAttester(byte[] buffer, short offset) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        P256Constants.setCurve(ecPrivateKey);
        ecPrivateKey.setS(buffer, offset, (short) 32);
        attester.init(ecPrivateKey, Signature.MODE_SIGN);
    }

    /**
     * Pack the length of a string or byte array as CBOR into a given buffer
     *
     * @param outBuf Buffer into which to write
     * @param writeIdx write index into given buffer
     * @param v Length value to be packed
     * @param byteString If true, value is the length of a byte string; if false, character string
     *
     * @return new write index after packing
     */
    private short encodeIntLenTo(byte[] outBuf, short writeIdx, short v, boolean byteString) {
        if (v < 24) {
            outBuf[writeIdx++] = (byte)((byteString ? 0x40 : 0x60) + v); // string with inline length
        } else if (v < 256) {
            outBuf[writeIdx++] = (byte)(byteString ? 0x58 : 0x78); // string: one byte length
            outBuf[writeIdx++] = (byte) v;
        } else {
            outBuf[writeIdx++] = (byte)(byteString ? 0x59 : 0x79); // string: two-byte length
            writeIdx = Util.setShort(outBuf, writeIdx, v);
        }
        return writeIdx;
    }

    /**
     * Sets in-memory variables capturing possible incoming CTAP options to their default values
     */
    private void defaultOptions() {
        transientStorage.defaultOptions();
    }

    /**
     * Reads a CBOR "options" map from an input buffer. After call, in-memory booleans corresponding to
     * the passed options are set as dictated by the input
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Read index into request buffer
     * @param lc Length of incoming request, as sent by the platform
     * @param requireUP Disallow UP=false, and set UP=true afterwards if option omitted
     * @param allowRK If false, error on the RK option (with any value)
     *
     * @return New read index after consuming the options map object
     */
    private short processOptionsMap(APDU apdu, byte[] buffer, short readIdx, short lc, boolean requireUP, boolean allowRK) {
        short numOptions = getMapEntryCount(apdu, buffer[readIdx++]);
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        for (short j = 0; j < numOptions; j++) {
            if ((buffer[readIdx] & 0xF0) != 0x60) { // string
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            short optionStrLen = (short)(buffer[readIdx++] & 0x0F);
            if (optionStrLen != 2 || (buffer[readIdx] != 'u' && buffer[readIdx] != 'r')) {
                // unknown option; ignore it and its value
                readIdx += optionStrLen;
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                continue;
            }

            if (buffer[readIdx] == 'r' && buffer[(short)(readIdx+1)] == 'k') {
                // rk option
                readIdx += 2;
                if (buffer[readIdx] == (byte) 0xF5) { // true
                    transientStorage.setRKOption(true);
                } else if (buffer[readIdx] == (byte) 0xF4) { // false
                    transientStorage.setRKOption(false);
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (!allowRK) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                }
            } else {
                short pOrVPos = ++readIdx;

                if (buffer[pOrVPos] != 'p' && buffer[pOrVPos] != 'v') {
                    // unknown two-character option starting with 'u'...
                    readIdx++;
                    readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                    continue;
                }

                byte val = buffer[++readIdx];
                if (val == (byte) 0xF5) { // true
                    if (buffer[pOrVPos] == 'p') {
                        transientStorage.setUPOption(true);
                    } else {
                        transientStorage.setUVOption(true);
                    }
                } else if (val == (byte) 0xF4) { // false
                    if (buffer[pOrVPos] == 'p') {
                        if (requireUP) {
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                        }
                        transientStorage.setUPOption(false);
                    } else {
                        transientStorage.setUVOption(false);
                    }
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            }
            readIdx++;
        }

        if (requireUP) {
            // UP defaults to true in this case
            transientStorage.setUPOption(true);
        }

        return readIdx;
    }

    /**
     * Pulls decrypted HMAC secret salts out of input CBOR message and places them in an output buffer
     *
     * @param apdu      Request/response object
     * @param buffer    Buffer containing incoming request
     * @param readIdx   Read index into request buffer
     * @param lc        Length of incoming request, as sent by the platform
     * @param outBuffer Output buffer into which to pack salt - needs at least 64 bytes of space
     * @param outOffset Offset into output buffer for writing salt
     * @param checkOnly If true, don't actually DO any HMAC-ing: just check salts have correct lengths
     * @return bitfield: salt length in bytes (32 or 64) plus PIN protocol (1 or 2)
     */
    private byte extractHMACSalt(APDU apdu, byte[] buffer, short readIdx, short lc,
                                 byte[] outBuffer, short outOffset, boolean checkOnly) {
        short mapType = buffer[readIdx++];
        if (mapType != (byte) 0xA3 && mapType != (byte) 0xA4) { // map, three or four entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (readIdx >= (short)(lc - (CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE.length + KEY_POINT_LENGTH * 2 + 7))) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        byte pinProtocol = 1;
        if (mapType == (byte) 0xA4) { // explicit pin protocol provided
            // Scan forward to find the pinProtocol block within the HMAC map
            // it can be set independently of the outer PIN protocol... yuck.
            short ppOffset = readIdx;
            for (byte i = 1; i < 4; i++) {
                if (buffer[ppOffset++] != i) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
                }
                ppOffset = consumeAnyEntity(apdu, buffer, ppOffset, lc);
            }
            if (buffer[ppOffset++] != 0x04) { // pin Protocol in advance :-)
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            pinProtocol = buffer[ppOffset];
            checkPinProtocolSupported(apdu, pinProtocol);
        }

        if (buffer[readIdx++] != 0x01) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (checkOnly) {
            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
        } else {
            readIdx = consumeKeyAgreement(apdu, buffer, readIdx, pinProtocol, lc);
        }

        if (buffer[readIdx++] != 0x02) { // map key: saltEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] != 0x58) { // byte string: one byte length
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        byte saltLenWithIV = buffer[readIdx++];
        byte saltLen = saltLenWithIV;
        short expectedBaseLen = 32;
        if (pinProtocol == 2) {
            expectedBaseLen += 16; // 16-byte IV for decryption
        }
        if (saltLenWithIV != expectedBaseLen && saltLenWithIV != (short)(expectedBaseLen + 32)) { // Standard says one or two 32-byte salts
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
        }
        short saltIdx = readIdx;

        if (readIdx >= (short)(lc - saltLenWithIV - 2 - 16)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (pinProtocol == 2) {
            saltLen -= 16; // "real" salt length shouldn't include the IV
        }
        if (checkOnly) {
            // We are now done checking the lengths
            return (byte)(saltLen + pinProtocol);
        }

        final short scratchAmt = 32;
        final short scratchHandle = bufferManager.allocate(apdu, scratchAmt, BufferManager.ANYWHERE);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
        readIdx = sharedSecretDecrypt(apdu, buffer, readIdx, lc, saltLen,
                outBuffer, outOffset, pinProtocol, false);

        if (buffer[readIdx++] != 0x03) { // map key: saltAuth
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        byte expectedSaltAuthLen = 16;
        if (pinProtocol == 2) {
            expectedSaltAuthLen = 32;
        }
        if (expectedSaltAuthLen < 24) {
            if (buffer[readIdx++] != (byte)(0x40 + expectedSaltAuthLen)) { // byte string with included length
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else {
            if (buffer[readIdx++] != 0x58) { // byte string, one-byte length
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (buffer[readIdx++] != expectedSaltAuthLen) { // fixed length
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        }

        hmacSha256(apdu, sharedSecretVerifyKey, (short) 0,
                buffer, saltIdx, saltLenWithIV,
                scratch, scratchOff
        );

        if (Util.arrayCompare(scratch, scratchOff,
                buffer, readIdx, expectedSaltAuthLen
        ) != 0) {
            // We must have gotten the crypto wrong somehow... (or the platform sent incorrect vals)
            // our computed HMAC didn't match the input
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
        }

        bufferManager.release(apdu, scratchHandle, scratchAmt);

        return (byte)(saltLen + pinProtocol);
    }

    /**
     * Does the math for the FIDO2 hmac-secret extension. After call, the APDU
     * buffer (starting at byte 0) contains a blob appropriate to send back to the platform as the value
     * produced by the hmac-secret extension.
     *
     * @param apdu Request/response object
     * @param privateKey Private key from which to get HMAC secret material
     * @param saltBuf Buffer containing HMAC secret salt(s)
     * @param saltOff Offset in salt buffer for start of salt(s)
     * @param saltLen Length of salt(s)
     * @param pinProtocol Integer PIN protocol version in use
     * @param outBuf Buffer into which to store output - must contain at least 80 bytes! NOTE: NOT ONLY 64 BYTES
     * @param outOff Offset into output buffer to start writing
     * @param uv Whether user verification was performed
     *
     * @return Length of HMAC secret data in output buffer
     */
    private short computeHMACSecret(APDU apdu, ECPrivateKey privateKey, byte[] saltBuf, short saltOff, short saltLen,
                                    byte pinProtocol, byte[] outBuf, short outOff, boolean uv) {
        // Position the hashes, pre-encryption, with 16 bytes padding at their start
        // that way if we are using PIN protocol 2 and encrypting adds a 16 byte IV to the beginning, we still
        // won't clobber the key before using it!
        final short firstOff = (short)(outOff + 16);
        final short secondOff = (short)(outOff + 48);

        // We will derive the HMAC secret key from the credential private key and an on-device key
        // ... by doing an HMAC-SHA256 of the credential private key using the HMAC-specific on-device key
        privateKey.getS(outBuf, outOff);

        // Derive the HMAC secret from the private key by taking the credential private key,
        // doing an HMAC-SHA256 on it...
        byte[] hmacWrapperBytes = uv ? hmacWrapperBytesUV : hmacWrapperBytesNoUV;
        hmacSha256(apdu, hmacWrapperBytes, (short) 0,
                outBuf, outOff, (short) 32,
                outBuf, outOff);
        // ... and then use that as our HMAC secret!

        if (saltLen == 64) {
            // if there's a second salt, HMAC that too
            hmacSha256(apdu, outBuf, outOff,
                    saltBuf, (short)(saltOff + 32), (short) 32,
                    outBuf, secondOff);
        }
        // HMAC the first salt - done in reverse order so we can clobber the key with this one
        hmacSha256(apdu, outBuf, outOff,
                saltBuf, saltOff, (short) 32,
                outBuf, firstOff);

        // encrypt the salted hashes using the shared secret, and that's our result
        return (short)(sharedSecretEncrypt(outBuf, firstOff, saltLen,
                outBuf, outOff, pinProtocol, false) - outOff);
    }

    private boolean checkCredential(APDU apdu, short rkNum,
                                    byte[] rpIdBuf, short rpIdHashIdx,
                                    byte[] outputBuffer, short outputOffset,
                                    byte maximumCredProtectLevel) {
        return checkCredential(apdu, residentKeys[rkNum].getEncryptedCredentialID(), (short) 0, residentKeys[rkNum].getCredLen(),
                rpIdBuf, rpIdHashIdx,
                outputBuffer, outputOffset,
                rkNum, maximumCredProtectLevel);
    }

    /**
     * Deciphers a credential ID block and compares its RP hash ID with a given value.
     * Before call, the symmetric secret must be initialized.
     * After call, the output buffer will contain: RPIDHash || credPrivateKey
     *
     * @param apdu request/response object
     * @param credentialBuffer Buffer containing the credential ID
     * @param credentialOffset Index of the credential ID block in the incoming buffer
     * @param credentialLen Length of the credential ID, as sent by the platform
     * @param rpIdBuf Buffer containing the RP ID hash
     * @param rpIdHashIdx Index of the RP ID hash within the given buffer
     * @param outputBuffer Buffer into which to store the decoded credential ID's private key -
     *                     needs CREDENTIAL_PAYLOAD_LEN bytes available
     * @param outputOffset Offset into the output buffer for write
     * @param rkNum if the credential was created as a resident/discoverable key, its index; -1 otherwise
     * @param maximumCredProtectLevel only return credentials with this security level or lower
     *
     * @return true if the credential decrypts to match the given RP ID hash, false otherwise
     */
    private boolean checkCredential(APDU apdu, byte[] credentialBuffer, short credentialOffset, short credentialLen,
                                    byte[] rpIdBuf, short rpIdHashIdx,
                                    byte[] outputBuffer, short outputOffset,
                                    short rkNum, byte maximumCredProtectLevel) {
        if (credentialLen != CREDENTIAL_ID_LEN) {
            // Someone's playing silly games...
            return false;
        }

        hmacSha256(apdu, credentialVerificationKey, (short) 0,
                credentialBuffer, credentialOffset, (short)(CREDENTIAL_PAYLOAD_LEN + IV_LEN - 14),
                outputBuffer, outputOffset);

        if (Util.arrayCompare(credentialBuffer, (short)(credentialOffset + CREDENTIAL_ID_LEN - 16),
                outputBuffer, outputOffset, (short) 16) != 0) {
            // credential HMAC failed to validate
            return false;
        }

        // Use these vars to avoid unnecessary decryption attempts
        boolean potentiallyTryLowSecKey = !FORCE_ALWAYS_UV;
        boolean potentiallyTryHighSecKey = maximumCredProtectLevel >= 3;

        if (rkNum >= 0) {
            // Check credProtect level first, for resident keys
            byte credProtectLevel = residentKeys[rkNum].getCredProtectLevel();
            if (credProtectLevel > maximumCredProtectLevel) {
                // this cred is ignored because it's too high-security for this context
                return false;
            }
            if (!LOW_SECURITY_MAXIMUM_COMPLIANCE && (!USE_LOW_SECURITY_FOR_SOME_RKS || credProtectLevel > 2)) {
                // No point trying the low-sec key for credProtect=3 RKs, or if they're all "high security"
                potentiallyTryLowSecKey = false;
                potentiallyTryHighSecKey = true;
            }
            if (USE_LOW_SECURITY_FOR_SOME_RKS && credProtectLevel < 3) {
                // No point trying the high security key for "low security" RKs either
                potentiallyTryHighSecKey = false;
            }
        }

        boolean matches = false;

        if (potentiallyTryHighSecKey) {
            final byte gottenCredProtLevelMixed = extractCredentialMixed(credentialBuffer, credentialOffset,
                    outputBuffer, outputOffset,
                    highSecurityWrappingKey);
            final boolean wasRKPreviously = (gottenCredProtLevelMixed & 0x80) != 0;
            final byte gottenCredProtLevel = (byte)(gottenCredProtLevelMixed & 0x7F);

            matches = gottenCredProtLevel <= maximumCredProtectLevel && (!wasRKPreviously || rkNum >= 0);

            // check RP ID
            if (Util.arrayCompare(outputBuffer, outputOffset,
                    rpIdBuf, rpIdHashIdx, RP_HASH_LEN) != 0) {
                matches = false;
            }
        }

        if (!matches && potentiallyTryLowSecKey) {
            // Try (again?) with the low-security key
            final byte gottenCredProtLevelMixed = extractCredentialMixed(credentialBuffer, credentialOffset,
                    outputBuffer, outputOffset,
                    lowSecurityWrappingKey);
            final boolean wasRKPreviously = (gottenCredProtLevelMixed & 0x80) != 0;
            final byte gottenCredProtLevel = (byte)(gottenCredProtLevelMixed & 0x7F);

            matches = gottenCredProtLevel <= maximumCredProtectLevel && (!wasRKPreviously || rkNum >= 0);

            if (Util.arrayCompare(outputBuffer, outputOffset,
                    rpIdBuf, rpIdHashIdx, RP_HASH_LEN) != 0) {
                matches = false;
            }
        }

        if (!matches) {
            return false;
        }

        return true;
    }

    /**
     * As extractCredentialMixed, but using the appropriate key for a certain RK
     *
     * @param credentialBuffer Buffer containing the encrypted credential ID
     * @param credentialIndex Index of the credential ID in the input buffer
     * @param outputBuffer Buffer to contain the mixed credential bytes
     * @param outputOffset Offset into output buffer
     * @param residentKeyNum RK index
     * @return credential protection level for the RK, with high bit set if a discoverable cred
     */
    private byte extractRKMixed(byte[] credentialBuffer, short credentialIndex,
                                byte[] outputBuffer, short outputOffset, short residentKeyNum) {
        final AESKey key = getAESKeyForExistingRK(residentKeyNum);
        return extractCredentialMixed(credentialBuffer, credentialIndex,
                outputBuffer, outputOffset, key);
    }

    /**
     * Extract a credential, without checking the stuff inside it.
     *
     * After call, the output buffer begins with the RP ID hash from the cred.
     *
     * @param credentialBuffer Buffer containing the encrypted credential ID
     * @param credentialOffset Index of the credential ID in the input buffer
     * @param outputBuffer Buffer to contain the mixed credential bytes
     * @param outputOffset Offset into output buffer
     * @param key key to use for decrypting the credential
     * @return The credential-protection level of the returned cred, if it's valid, with the high bit set for RK
     */
    private byte extractCredentialMixed(byte[] credentialBuffer, short credentialOffset,
                                        byte[] outputBuffer, short outputOffset,
                                        AESKey key) {
        symmetricUnwrapper.init(key, Cipher.MODE_DECRYPT, credentialBuffer, credentialOffset, IV_LEN);
        final short ret = symmetricUnwrapper.doFinal(credentialBuffer, (short)(credentialOffset + IV_LEN), CREDENTIAL_PAYLOAD_LEN,
                outputBuffer, outputOffset);
        if (ret != CREDENTIAL_PAYLOAD_LEN) {
            throwException(ISO7816.SW_DATA_INVALID);
        }
        return outputBuffer[(short)(outputOffset + RP_HASH_LEN + KEY_POINT_LENGTH)];
    }

    /**
     * Sets up state tracking for a chained (long) response to the platform, and sends the appropriate status code.
     * Should only be called after the first packet in the chain is sent.
     *
     * @param offset The offset into the response buffer from which to begin the next packet
     * @param remaining The total number of bytes remaining after the already-sent packet
     */
    private void setupChainedResponse(short offset, short remaining) {
        transientStorage.setOutgoingContinuation(offset, remaining);
        if (remaining >= 256) {
            // at least ANOTHER full chunk remains
            throwException(ISO7816.SW_BYTES_REMAINING_00, false);
        } else {
            // exactly one more chunk remains
            throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + remaining), false);
        }
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
        bufferManager.clear();

        final boolean x5c = transientStorage.shouldStreamX5CLater();
        final boolean lbk = transientStorage.shouldStreamLBKLater();
        final boolean isExtendedAPDU = apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA;
        final short apduBlockSize = (short)(APDU.getOutBlockSize() - 2);
        final short expectedLen = apdu.setOutgoing();

        short totalOutputLen = outputLen;
        if (x5c) {
            totalOutputLen = (short)(totalOutputLen + attestationData.length);
        }
        if (lbk) {
            totalOutputLen = (short)(totalOutputLen + 35); // 1 byte map key, 2 bytes CBOR array, 32 bytes LBK
        }

        short amountFitInBuffer = totalOutputLen;
        if (amountFitInBuffer > expectedLen) {
            amountFitInBuffer = expectedLen;
        }
        if (amountFitInBuffer > apduBlockSize) {
            amountFitInBuffer = apduBlockSize;
        }

        short amountFromMem = amountFitInBuffer;
        if (amountFromMem > outputLen) {
            amountFromMem = outputLen;
        }

        if (isExtendedAPDU) {
            apdu.setOutgoingLength(totalOutputLen);
        } else {
            apdu.setOutgoingLength(amountFitInBuffer);
        }
        final byte[] apduBytes = apdu.getBuffer();
        Util.arrayCopyNonAtomic(bufferMem, (short) 0,
                apduBytes, (short) 0, amountFromMem);
        if (x5c) {
            // Stash the amount of bufmem that was validly filled
            transientStorage.setStoredVars(outputLen, (byte) -1);
            if (amountFromMem < amountFitInBuffer) {
                // We can send some X5C bytes, too!
                short availableForX5C = (short) (amountFitInBuffer - amountFromMem);
                if (availableForX5C > attestationData.length) {
                    availableForX5C = (short) attestationData.length;
                }
                Util.arrayCopyNonAtomic(attestationData, (short) 0,
                        apduBytes, amountFromMem, availableForX5C);

                if (availableForX5C == attestationData.length) {
                    // ... and we still have room for more: let's go send the LBK stuff!
                    short availableForLBK = (short) (amountFitInBuffer - amountFromMem - availableForX5C);
                    if (availableForLBK > 35) {
                        availableForLBK = 35;
                    }
                    Util.arrayCopyNonAtomic(bufferMem, (short)(bufferMem.length - 36),
                            apduBytes, (short)(amountFromMem + availableForX5C), availableForLBK);
                }
            }
        }
        apdu.sendBytes((short) 0, amountFitInBuffer);
        if (totalOutputLen > amountFitInBuffer) {
            // we're not done; set state to continue response delivery later, with chaining
            if (isExtendedAPDU) {
                transientStorage.setOutgoingContinuation(amountFitInBuffer, (short)(totalOutputLen - amountFitInBuffer));
                // deliver it right now, by repeatedly overwriting the APDU buffer
                while (!streamOutgoingContinuation(apdu, apduBytes, false));
            } else {
                setupChainedResponse(amountFitInBuffer, (short)(totalOutputLen - amountFitInBuffer));
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
    private static short ub(byte b) {
        return (short)(0xFF & b);
    }

    /**
     * Consumes and discards an arbitrary CBOR object. Is recursive, so relies on FIDO2 nesting depth standard to
     * avoid stack overflow in valid cases.
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Current index into incoming request buffer
     * @param lc Length of request, as sent by the platform
     *
     * @return New index into incoming request buffer after consuming one CBOR object of any type
     */
    private short consumeAnyEntity(APDU apdu, byte[] buffer, short readIdx, short lc) {
        if (readIdx >= lc || readIdx < 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        byte b = buffer[readIdx];
        short s = ub(b);

        if ((s >= 0x0000 && s <= 0x0017) || (s >= 0x0020 && s <= 0x0037) || s == 0x00F4 || s == 0x00F5 || s == 0x00F6) {
            return (short)(readIdx + 1);
        }
        if (s == 0x0018 || s == 0x0038) {
            return (short) (readIdx + 2);
        }
        if (s == 0x0019 || s == 0x0039) {
            return (short) (readIdx + 3);
        }
        if (s == 0x0058 || s == 0x0078) {
            return (short) (readIdx + 2 + ub(buffer[(short)(readIdx+1)]));
        }
        if (s == 0x0059 || s == 0x0079) {
            short len = Util.getShort(buffer, (short)(readIdx + 1));
            if (len < 0) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            return (short) (readIdx + 3 + len);
        }
        if (s >= 0x0040 && s <= 0x0057) {
            return (short)(readIdx + 1 + s - 0x0040);
        }
        if (s >= 0x0060 && s <= 0x0077) {
            return (short)(readIdx + 1 + s - 0x0060);
        }
        if (s == 0x0098) {
            short l = ub(buffer[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0x0099) {
            short l = Util.getShort(buffer, (short)(readIdx + 1));
            if (l == Short.MAX_VALUE || l < 0) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            readIdx += 3;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s >= 0x0080 && s <= 0x0097) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0x0080); i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s >= 0x00A0 && s <= 0x00B7) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0x00A0); i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0x00B8) {
            short l = ub(buffer[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }

        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        return readIdx;
    }

    /**
     * Consumes a CBOR map and locates the element having string key "id". After call, temp variables
     * representing the index and length of the matched value are set, if a match was found.
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Current index into the request buffer
     * @param lc Length of the request buffer, as sent by the platform
     * @param byteString If true, returned value should be a byte string: if false, a UTF-8 string
     * @param checkTypePublicKey If true, check there is a "type" key with value UTF-8 string "public-key"
     * @param checkAllFieldsText If true, check that all fields other than the "id" are of type text
     * @param findName If true, find the "name" key (if one exists) instead of "id"
     *
     * @return New index into the request buffer, after consuming one CBOR map element
     */
    private short consumeMapAndGetID(APDU apdu, byte[] buffer, short readIdx, short lc, boolean byteString,
                                     boolean checkTypePublicKey, boolean checkAllFieldsText, boolean findName) {
        boolean foundTargetField = false;
        boolean foundType = false;
        boolean correctType = false;
        transientStorage.readyStoredVars();
        short mapDef = ub(buffer[readIdx++]);
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        short mapEntryCount = 0;
        if ((mapDef & 0xF0) == 0xA0) {
            mapEntryCount = (short) (mapDef & 0x0F);
        } else if ((mapDef & 0xF0) == 0xB0 && mapDef < ub((byte) 0xB8)) {
            mapEntryCount = (short) ((mapDef & 0x0F) + 16);
        } else if (mapDef == (byte) 0xB8) {
            mapEntryCount = ub(buffer[readIdx++]);
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        for (short i = 0; i < mapEntryCount; i++) {
            final short keyDef = ub(buffer[readIdx++]);
            short keyLen = 0;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            if (keyDef == 0x0078) {
                keyLen = ub(buffer[readIdx++]);
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
            } else if (keyDef >= 0x0060 && keyDef < 0x0078) {
                keyLen = (short)(keyDef - 0x0060);
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            final boolean isId = (keyLen == 2 && buffer[readIdx] == 'i' && buffer[(short)(readIdx+1)] == 'd');
            if (isId && foundTargetField && !findName) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            final boolean isType = (keyLen == 4 && buffer[readIdx] == 't' && buffer[(short)(readIdx+1)] == 'y'
                && buffer[(short)(readIdx+2)] == 'p' && buffer[(short)(readIdx+3)] == 'e');
            if (isType && foundType) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            final boolean isName = (keyLen == 4 && buffer[readIdx] == 'n' && buffer[(short)(readIdx+1)] == 'a'
                    && buffer[(short)(readIdx+2)] == 'm' && buffer[(short)(readIdx+3)] == 'e');
            if (isName && foundTargetField && findName) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            readIdx += keyLen;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            short valDef = ub(buffer[readIdx++]);
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            short targetPos = readIdx;

            short valLen = 0;
            if (valDef == 0x0078 || valDef == 0x0058) {
                if ((isId && !findName) || (isName && findName)) {
                    if (valDef == 0x0078 && byteString) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    } else if (valDef == 0x0058 && !byteString) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                }
                if (isType && valDef == 0x0058) {
                    // heh, literally "unexpected type" here
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (checkAllFieldsText && !isId && valDef == 0x0058) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                valLen = ub(buffer[readIdx++]);
                if (isId || isName) {
                    targetPos++;
                }
                if (readIdx >= lc) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
            } else if (valDef == 0x0079) {
                if (isId) {
                    // Whoa nelly.
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                valLen = Util.getShort(buffer, readIdx);
                if (valLen < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                readIdx += 2;
            } else if (valDef >= 0x0060 && valDef < 0x0078) {
                if (isId && byteString && !findName) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (isName && byteString && findName) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                valLen = (short)(valDef - 0x0060);
            } else if (valDef >= 0x0040 && valDef < 0x0058) {
                if (isId && !findName && !byteString) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (isName && findName && !byteString) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (isType) {
                    // byte strings aren't valid for public-key types...
                    foundType = true;
                    correctType = false;
                }
                if (checkAllFieldsText && !isId) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                valLen = (short) (valDef - 0x0040);
            } else {
                if (isId || isType || isName) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (checkAllFieldsText) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                valLen = (short)(consumeAnyEntity(apdu, buffer, (short)(readIdx - 1), lc) - readIdx);
            }

            if (isId) {
                if (valLen > 255) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
                }
                if (!findName) {
                    foundTargetField = true;
                    transientStorage.setStoredVars(targetPos, (byte) valLen);
                }
            }

            if (isName) {
                if (valLen > 255) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
                }
                if (findName) {
                    foundTargetField = true;
                    transientStorage.setStoredVars(targetPos, (byte) valLen);
                }
            }

            if (!foundType && isType && checkTypePublicKey) {
                foundType = true;
                correctType = valLen == (short) CannedCBOR.PUBLIC_KEY_TYPE.length
                  && Util.arrayCompare(buffer, readIdx,
                        CannedCBOR.PUBLIC_KEY_TYPE, (short) 0, valLen) == 0;
            }

            readIdx += valLen;
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
        }

        if (!foundTargetField) {
            if (!findName) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }
            // Empty result for a missing name - 0 pos, 0 length
            transientStorage.setStoredVars((short) 0, (byte) 0);
        }

        if (checkTypePublicKey) {
            if (!foundType) {
                // entirely missing "type" field
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }

            if (!correctType) {
                // We found an ID entry, but it's not of type "public-key" - treat it as if we found nothing
                transientStorage.readyStoredVars();
            }
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
        if (selectingApplet()) {
            handleAppletSelect(apdu);

            return;
        }

        final byte[] apduBytes = apdu.getBuffer();

        final short cla_ins = Util.getShort(apduBytes, ISO7816.OFFSET_CLA);
        final short p1_p2 = Util.getShort(apduBytes, ISO7816.OFFSET_P1);

        if (cla_ins == (short) 0x8012 && p1_p2 == (short) 0x0100) {
            // Explicit disable command (NFCCTAP_CONTROL end CTAP_MSG). Turn off, and stay off.
            transientStorage.disableAuthenticator();
        }

        if (cla_ins == (short) 0x00A4 && p1_p2 == (short) 0x0400) {
            // Applet-select command, probably part of test shenanigans
            handleAppletSelect(apdu);
            return;
        }

        if (transientStorage.authenticatorDisabled()) {
            return;
        }

        if (cla_ins == 0x00C0 || cla_ins == (short) 0x80C0) {
            streamOutgoingContinuation(apdu, apduBytes, true);
            return;
        } else {
            if (transientStorage.getLargeBlobWriteOffset() == -1) {
                // Preserve cross-request large blob statekeeping
                transientStorage.clearOutgoingContinuation();
            }
        }

        if (attestationData != null && filledAttestationData < attestationData.length &&
                transientStorage.getChainIncomingReadOffset() > 0 &&
                bufferMem[0] == FIDOConstants.CMD_INSTALL_CERTS
            ) {
            // Still waiting to receive more cert data
            final short amtRead = apdu.setIncomingAndReceive();

            final short lc = apdu.getIncomingLength();
            if (lc == 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            byte[] buf = fullyReadReq(apdu, lc, amtRead, true);
            final boolean done = initAttestationKeyContinue(apdu, buf,
                    (short) 1, lc);
            transientStorage.resetChainIncomingReadOffset();
            if (!done) {
                // Keep the command byte
                transientStorage.increaseChainIncomingReadOffset((short) 1);
            }
            return;
        } else if (apdu.isCommandChainingCLA()) {
            // Incoming chained request
            final short amtRead = apdu.setIncomingAndReceive();

            final short lc = apdu.getIncomingLength();
            if (lc == 0) {
                // No data?
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            fullyReadReq(apdu, lc, amtRead, true);
            if (attestationSwitchingEnabled
                    && bufferMem[0] == FIDOConstants.CMD_INSTALL_CERTS) {
                // Stream cert install, which can be very large, directly
                boolean done = false;
                if (attestationData == null) {
                    // Initial attestation data
                    final short apOffset = (short)(apdu.getOffsetCdata() + 1);
                    final short lcEffective = (short)(lc - apOffset);
                    done = initAttestationKeyStart(apdu, bufferMem,
                            apOffset,
                            lcEffective
                    );
                } else {
                    // How did we get here?
                    throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                transientStorage.resetChainIncomingReadOffset();
                if (!done) {
                    // Keep the command byte
                    transientStorage.increaseChainIncomingReadOffset((short) 1);
                }
                return;
            } else {
                transientStorage.increaseChainIncomingReadOffset(lc);
            }

            return;
        }

        if (cla_ins == 0x0001) {
            transientStorage.clearOutgoingContinuation();
            u2FRegister(apdu);
            return;
        } else if (cla_ins == 0x0002) {
            transientStorage.clearOutgoingContinuation();
            if (apduBytes[ISO7816.OFFSET_P2] != 0x00) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            byte p1 = apduBytes[ISO7816.OFFSET_P1];
            if (p1 != 0x03 && p1 != 0x07 && p1 != 0x08) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            u2FAuthenticate(apdu, p1);
            return;
        } else if (cla_ins == 0x0003) {
            // U2F VERSION
            if (p1_p2 != 0x0000) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            sendByteArray(apdu, CannedCBOR.U2F_V2_RESPONSE,
                    (short) CannedCBOR.U2F_V2_RESPONSE.length);
            return;
        }

        initKeyAgreementKeyIfNecessary();

        if (apduBytes[ISO7816.OFFSET_CLA] != (byte) 0x80) {
            throwException(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (apduBytes[ISO7816.OFFSET_INS] != 0x10) {
            throwException(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        if ((apduBytes[ISO7816.OFFSET_P1] != 0x00 && apduBytes[ISO7816.OFFSET_P1] != (byte) 0x80) || apduBytes[ISO7816.OFFSET_P2] != 0x00) {
            throwException(ISO7816.SW_INCORRECT_P1P2);
        }

        final short amtRead = apdu.setIncomingAndReceive();
        final short lc = apdu.getIncomingLength();

        if (amtRead == 0) {
            throwException(ISO7816.SW_DATA_INVALID);
        }

        short lcEffective = (short)(lc + 1);
        byte cmdByte = apduBytes[apdu.getOffsetCdata()];

        if (cmdByte != FIDOConstants.CMD_LARGE_BLOBS) {
            // Any command other than large blobs should reset the large-blob statekeeping
            transientStorage.clearOutgoingContinuation();
        }

        short chainingReadOffset = transientStorage.getChainIncomingReadOffset();
        if (chainingReadOffset > 0) {
            cmdByte = bufferMem[0];
            lcEffective += chainingReadOffset;
        }

        if (cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT
            && cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT_PREVIEW) {
            transientStorage.clearIterationPointers();
        }

        if (cmdByte != FIDOConstants.CMD_GET_NEXT_ASSERTION) {
            transientStorage.clearAssertIterationPointer();
        }

        bufferManager.initializeAPDU(apdu);

        byte[] reqBuffer;

        switch (cmdByte) {
            case FIDOConstants.CMD_MAKE_CREDENTIAL:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

                makeCredential(apdu, lcEffective, reqBuffer);
                break;
            case FIDOConstants.CMD_GET_INFO:
                sendAuthInfo(apdu);
                break;
            case FIDOConstants.CMD_GET_ASSERTION:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

                getAssertion(apdu, lcEffective, reqBuffer, (short) 0);
                break;
            case FIDOConstants.CMD_GET_NEXT_ASSERTION:
                if (transientStorage.getAssertIterationPointer() <= 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
                }
                // Note: no fullyReadReq here, because we already put the meaningful input parameters into scratch

                // We set lc to a high value here because we ALREADY successfully processed the request once,
                // back when it was a normal getAssertion call. We know it's valid... enough.
                getAssertion(apdu, Short.MAX_VALUE, null, transientStorage.getAssertIterationPointer());
                break;
            case FIDOConstants.CMD_CLIENT_PIN:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

                clientPINSubcommand(apdu, reqBuffer, lcEffective);
                break;
            case FIDOConstants.CMD_RESET:
                authenticatorReset(apdu);
                break;
            case FIDOConstants.CMD_CREDENTIAL_MANAGEMENT: // intentional fallthrough, for backwards compat
            case FIDOConstants.CMD_CREDENTIAL_MANAGEMENT_PREVIEW:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

                credManagementSubcommand(apdu, reqBuffer, lcEffective);
                break;
            case FIDOConstants.CMD_AUTHENTICATOR_SELECTION:
                authenticatorSelection(apdu);
                break;
            case FIDOConstants.CMD_LARGE_BLOBS:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

                handleLargeBlobs(apdu, reqBuffer, lcEffective);
                break;
            case FIDOConstants.CMD_AUTHENTICATOR_CONFIG:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, false);

                authenticatorConfigSubcommand(apdu, reqBuffer, lcEffective);
                break;
            case FIDOConstants.CMD_INSTALL_CERTS:
                boolean extended = apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA;
                short apOffset;
                lcEffective = (short)(lc - 5);
                reqBuffer = fullyReadReq(apdu, lc, amtRead, !extended);
                if (extended) {
                    apOffset = (short)(apdu.getOffsetCdata() - 2);
                    if (lc > 255) {
                        apOffset += 1;
                        lcEffective -= 1;
                    }
                } else {
                    apOffset = apdu.getOffsetCdata();
                }
                initAttestationKeyStart(apdu, reqBuffer, apOffset, lcEffective);
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_COMMAND);
                break;
        }

        transientStorage.resetChainIncomingReadOffset();
    }

    private byte[] getCurrentLargeBlobStore() {
        if (largeBlobStoreIndex == 0) {
            return largeBlobStoreA;
        }
        return largeBlobStoreB;
    }

    private byte[] getInactiveLargeBlobStore() {
        if (largeBlobStoreIndex == 1) {
            return largeBlobStoreA;
        }
        return largeBlobStoreB;
    }

    /**
     * Processes CTAP2 largeBlob extension commands
     *
     * @param apdu Request/response context object
     * @param reqBuffer Incoming request buffer
     * @param lc Declared length of incoming request in bytes
     */
    private void handleLargeBlobs(APDU apdu, byte[] reqBuffer, short lc) {
        short readIdx = 1;

        short getBytes = -1;
        short setIdx = -1;
        short setIncomingDataLength = -1;
        short setTotalLength = -1;
        short offset = -1;
        byte pinProtocol = 0;
        short pinUvAuthIdx = -1;
        short pinUvAuthLen = -1;

        short numParams = getMapEntryCount(apdu, reqBuffer[readIdx++]);

        for (short i = 0; i < numParams; i++) {
            if (readIdx > lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            switch (reqBuffer[readIdx++]) {
                case 0x01: // map key: get
                    byte getLenByte = reqBuffer[readIdx++];
                    if (getLenByte <= 0x17) {
                        getBytes = getLenByte;
                    } else if (getLenByte == 0x18) {
                        getBytes = ub(reqBuffer[readIdx++]);
                    } else if (getLenByte == 0x19) {
                        getBytes = Util.getShort(reqBuffer, readIdx);
                        readIdx += 2;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    if (getBytes < 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    break;
                case 0x02: // map key: set
                    byte setIncomingDataLenByte = reqBuffer[readIdx++];
                    if (setIncomingDataLenByte >= 0x40 && setIncomingDataLenByte <= 0x57) {
                        setIncomingDataLength = (short)(setIncomingDataLenByte - 0x40);
                    } else if (setIncomingDataLenByte == 0x58) {
                        setIncomingDataLength = ub(reqBuffer[readIdx++]);
                    } else if (setIncomingDataLenByte == 0x59) {
                        setIncomingDataLength = Util.getShort(reqBuffer, readIdx);
                        readIdx += 2;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    if (setIncomingDataLength < 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    setIdx = readIdx;
                    readIdx += setIncomingDataLength;
                    break;
                case 0x03: // map key: offset
                    byte offsetLenByte = reqBuffer[readIdx++];
                    if (offsetLenByte <= 0x17) {
                        offset = offsetLenByte;
                    } else if (offsetLenByte == 0x18) {
                        offset = ub(reqBuffer[readIdx++]);
                    } else if (offsetLenByte == 0x19) {
                        offset = Util.getShort(reqBuffer, readIdx);
                        readIdx += 2;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    if (offset < 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    break;
                case 0x04: // map key: length
                    byte setTotalLenByte = reqBuffer[readIdx++];
                    if (setTotalLenByte <= 0x17) {
                        setTotalLength = setTotalLenByte;
                    } else if (setTotalLenByte == 0x18) {
                        setTotalLength = ub(reqBuffer[readIdx++]);
                    } else if (setTotalLenByte == 0x19) {
                        setTotalLength = Util.getShort(reqBuffer, readIdx);
                        readIdx += 2;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    if (setTotalLength < 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    break;
                case 0x05: // map key: pinUvAuthParam
                    byte pinUvAuthLenByte = reqBuffer[readIdx++];
                    if (pinUvAuthLenByte >= 0x40 && pinUvAuthLenByte <= 0x57) {
                        pinUvAuthLen = (short)(pinUvAuthLenByte - 0x40);
                    } else if (pinUvAuthLenByte == 0x58) {
                        pinUvAuthLen = ub(reqBuffer[readIdx++]);
                    } else if (pinUvAuthLenByte == 0x59) {
                        pinUvAuthLen = Util.getShort(reqBuffer, readIdx);
                        readIdx += 2;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    if (pinUvAuthLen < 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    pinUvAuthIdx = readIdx;
                    readIdx += pinUvAuthLen;
                    break;
                case 0x06: // map key: pinUvAuthProtocol
                    pinProtocol = reqBuffer[readIdx++];
                    checkPinProtocolSupported(apdu, pinProtocol);
                    break;
                default:
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    break;
            }
        }

        if ((getBytes >= 0 && setIdx >= 0) || (getBytes < 0 && setIdx < 0)) {
            // Can either set or get, not both, not neither
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }

        byte[] currentLargeBlobStore = getCurrentLargeBlobStore();

        if (offset < 0 || offset > (short) currentLargeBlobStore.length) {
            // Offset is mandatory and must be reasonable
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }

        if (getBytes >= 0) {
            // get
            if (setTotalLength >= 0) {
                // Length not a valid param for gets
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }

            if (getBytes > MAX_FRAGMENT_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
            }

            if (pinUvAuthIdx != -1 || pinProtocol != 0) {
                // PIN parameters aren't just not checked for gets, they're actively disallowed
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }

            handleLargeBlobGet(apdu, getBytes, offset);
        } else {
            // set
            if (offset == 0) {
                if (setIncomingDataLength < 0 || setIncomingDataLength > MAX_FRAGMENT_LEN) {
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                }
                if (setTotalLength < 17) {
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                }
                if (setTotalLength > (short) currentLargeBlobStore.length) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL);
                }
            } else {
                if (setTotalLength != -1) {
                    // length can only be sent on initial write requests
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                }
                short expectedOffset = transientStorage.getLargeBlobWriteOffset();
                if (expectedOffset == -1 || expectedOffset != offset) {
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_SEQ);
                }

                setTotalLength = transientStorage.getLargeBlobWriteTotalLength();

                if ((short)(offset + setIncomingDataLength) > setTotalLength) {
                    // Too much data?
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
                }
            }

            if (pinSet || alwaysUv) {
                if (pinUvAuthIdx == -1) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
                }
                if (pinProtocol == 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
                }

                // check PIN token: build verification buffer first
                short scratchHandle = bufferManager.allocate(apdu, (short) 70, BufferManager.ANYWHERE);
                byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
                short scratchOffset = bufferManager.getOffsetForHandle(scratchHandle);

                Util.arrayFillNonAtomic(scratch, scratchOffset, (short) 32, (byte) 0xFF);
                short scratchW = (short)(scratchOffset + 32);
                scratch[scratchW++] = 0x0C;
                scratch[scratchW++] = 0x00;
                scratch[scratchW++] = (byte)(offset & 0xFF);
                scratch[scratchW++] = (byte)(offset >> 8);
                scratch[scratchW++] = 0x00;
                scratch[scratchW++] = 0x00;
                sha256.doFinal(reqBuffer, setIdx, setIncomingDataLength,
                        scratch, scratchW);

                byte pinPerms = transientStorage.getPinPermissions();

                checkPinToken(apdu, scratch, scratchOffset, (short) 70,
                        reqBuffer, pinUvAuthIdx, pinProtocol, true);

                if ((pinPerms & FIDOConstants.PERM_LARGE_BLOB_WRITE) == 0x00) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }

                bufferManager.release(apdu, scratchHandle, (short) 70);
            }

            handleLargeBlobSet(apdu, reqBuffer, setIdx, offset, setIncomingDataLength, setTotalLength);
        }
    }

    /**
     * Writes to the largeBlobStore
     *
     * @param apdu Request/response context object
     * @param buffer Incoming request buffer
     * @param incomingDataOffset Data to be written, as an offset in the incoming request buffer
     * @param blobWriteOffset Current write index into large blob store
     * @param incomingDataLength Number of bytes contained in this write request
     * @param totalLength Total length of new large-blob-store contents
     */
    private void handleLargeBlobSet(APDU apdu, byte[] buffer, short incomingDataOffset,
                                    short blobWriteOffset, short incomingDataLength, short totalLength) {
        final byte[] inactiveLargeBlobStore = getInactiveLargeBlobStore();
        Util.arrayCopyNonAtomic(buffer, incomingDataOffset,
                inactiveLargeBlobStore, blobWriteOffset, incomingDataLength);
        // Done with incoming request now
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

        short pendingFillLength = (short)(blobWriteOffset + incomingDataLength);
        if (pendingFillLength == totalLength) {
            // Done!

            // Check hash is valid
            short scratchHandle = bufferManager.allocate(apdu, (short) 32, BufferManager.ANYWHERE);
            byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
            short scratchOffset = bufferManager.getOffsetForHandle(scratchHandle);

            sha256.doFinal(inactiveLargeBlobStore, (short) 0, (short)(totalLength - 16),
                    scratch, scratchOffset);

            if (Util.arrayCompare(scratch, scratchOffset,
                    inactiveLargeBlobStore, (short)(totalLength - 16), (short) 16) != 0) {
                // hash mismatch
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
            }

            if (WRITES_INVALIDATE_PINS) {
                transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
            }

            bufferManager.release(apdu, scratchHandle, (short) 32);

            // Swapperoo the buffers
            final byte newBlobStoreIndex = (byte)(largeBlobStoreIndex == 0 ? 1 : 0);
            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                largeBlobStoreIndex = newBlobStoreIndex;
                largeBlobStoreFill = totalLength;
                ok = true;
            } finally {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }

            transientStorage.clearOutgoingContinuation();
        } else {
            // More yet to read
            transientStorage.setInLargeBlobWrite(pendingFillLength, totalLength);
        }

        apdu.getBuffer()[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Reads data from the large blob store
     *
     * @param apdu Request/response context object
     * @param numBytes Number of bytes requested
     * @param offset Read offset into the large blob store
     */
    private void handleLargeBlobGet(APDU apdu, short numBytes, short offset) {
        short bytesToRetrieve = 0;
        if (offset < largeBlobStoreFill) {
            bytesToRetrieve = (short)(largeBlobStoreFill - offset);
        }
        if (bytesToRetrieve > numBytes) {
            bytesToRetrieve = numBytes;
        }

        // Just puts data into bufferMem or the APDU buffer and sends it...
        byte[] outBuffer = bufferMem;
        if (bytesToRetrieve < 250) { // this will fit directly into the APDU buffer!
            outBuffer = apdu.getBuffer();
        }
        short writeIdx = 0;

        outBuffer[writeIdx++] = FIDOConstants.CTAP2_OK;
        outBuffer[writeIdx++] = (byte) 0xA1; // map - one key
        outBuffer[writeIdx++] = (byte) 0x01; // map key: config
        writeIdx = encodeIntLenTo(outBuffer, writeIdx, bytesToRetrieve, true);
        writeIdx = Util.arrayCopyNonAtomic(getCurrentLargeBlobStore(), offset,
                outBuffer, writeIdx, bytesToRetrieve);

        if (outBuffer == bufferMem) {
            doSendResponse(apdu, writeIdx);
        } else {
            sendNoCopy(apdu, writeIdx);
        }
    }

    /**
     * Implements the U2F AUTHENTICATE operation
     *
     * @param apdu Request/response context object
     * @param p1 Value of the ISO P1 parameter, used to determine if this is a check-only operation
     */
    private void u2FAuthenticate(APDU apdu, byte p1) {
        if (attestationData == null || filledAttestationData < attestationData.length) {
            // Authenticating requires an attestation certificate!
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if (alwaysUv) {
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        short amtRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        final byte[] reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

        final short clientDataHashOffset = 0;
        final short rpIdHashOffset = (short)(clientDataHashOffset + CLIENT_DATA_HASH_LEN);
        final short credIdLenOffset = (short)(rpIdHashOffset + RP_HASH_LEN);
        final short credIdOffset = (short)(credIdLenOffset + 1);
        if (lc != (short)(credIdOffset + CREDENTIAL_ID_LEN - clientDataHashOffset)) {
            throwException(ISO7816.SW_WRONG_LENGTH);
        }

        if (reqBuffer[credIdLenOffset] != CREDENTIAL_ID_LEN) {
            // Our credentials are all the same length...
            throwException(ISO7816.SW_WRONG_DATA);
        }

        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);

        // Allow using low-security RKs over U2F, because why not?
        final short rkIndex = scanRKsForExactCredential(reqBuffer, credIdOffset);

        final boolean match = checkCredential(apdu, reqBuffer, credIdOffset, CREDENTIAL_ID_LEN,
                reqBuffer, rpIdHashOffset,
                scratchCredBuffer, scratchCredOffset, rkIndex, (byte) 2);

        if (!match) {
            // Not a valid credential
            throwException(ISO7816.SW_WRONG_DATA);
        }

        if (p1 == 0x07) {
            // Just checking!
            throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        loadScratchIntoAttester(scratchCredBuffer, (short)(scratchCredOffset + RP_HASH_LEN));

        final byte flag_byte = 0x01; // User always present

        // From here, we got a match: sign and send

        final short scratchSigHandle = bufferManager.allocate(apdu,
                (short)(RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5), BufferManager.NOT_APDU_BUFFER);
        final short scratchSigOffset = bufferManager.getOffsetForHandle(scratchSigHandle);
        final byte[] scratchSigBuffer = bufferManager.getBufferForHandle(apdu, scratchSigHandle);

        random.generateData(scratchSigBuffer, scratchSigOffset, (short) 1);
        counter.increment((short)((scratchSigBuffer[scratchSigOffset] & 0x0E) + 1));

        final short sigRPIDOffset = scratchSigOffset;
        final short sigFlagsByteOffset = (short)(sigRPIDOffset + RP_HASH_LEN);
        final short sigCounterOffset = (short)(sigFlagsByteOffset + 1);
        final short sigClientDataOffset = (short)(sigCounterOffset + 4);

        // Shufflearoo to get things into the right order for signing
        Util.arrayCopyNonAtomic(reqBuffer, rpIdHashOffset,
                scratchSigBuffer, sigRPIDOffset, RP_HASH_LEN);
        scratchSigBuffer[sigFlagsByteOffset] = flag_byte;
        counter.pack(scratchSigBuffer, sigCounterOffset);
        Util.arrayCopyNonAtomic(reqBuffer, clientDataHashOffset,
                scratchSigBuffer, sigClientDataOffset, CLIENT_DATA_HASH_LEN);

        final byte[] apduBuf = apdu.getBuffer();
        final short sigLen = attester.sign(scratchSigBuffer, sigRPIDOffset,
                (short)(RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5),
                apduBuf, (short) 5);

        apduBuf[0] = flag_byte;
        counter.pack(apduBuf, (short) 1);
        sendNoCopy(apdu, (short)(sigLen + 5));
    }

    /**
     * Implements the U2F REGISTER operation
     *
     * @param apdu Request/response context object
     */
    private void u2FRegister(APDU apdu) {
        if (attestationData == null || filledAttestationData < attestationData.length) {
            // Registering requires an attestation certificate!
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if (alwaysUv) {
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        final short amtRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        if (lc != (short)(CLIENT_DATA_HASH_LEN + RP_HASH_LEN)) {
            throwException(ISO7816.SW_WRONG_LENGTH);
        }
        final byte[] reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

        // TODO: handle very long certificates
        short attCertLen = 0;
        byte cborAttLenByte = attestationData[1];
        short attCertStart = 2;
        if (cborAttLenByte < 0x57 && cborAttLenByte >= 0x40) {
            attCertLen = (short)(cborAttLenByte - 0x40);
        } else if (cborAttLenByte == 0x58) { // one-byte length
            attCertLen = ub(attestationData[attCertStart++]);
        } else if (cborAttLenByte == 0x59) { // two-byte length
            attCertLen = Util.getShort(attestationData, attCertStart);
            attCertStart += 2;
        } else {
            throwException(ISO7816.SW_DATA_INVALID);
        }

        short readOffset = 0;
        bufferManager.initializeAPDU(apdu);

        final short scratchClientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchClientDataHashOffset = bufferManager.getOffsetForHandle(scratchClientDataHashHandle);
        final byte[] scratchClientDataHashBuffer = bufferManager.getBufferForHandle(apdu, scratchClientDataHashHandle);
        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchRPIDHashOffset = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        final short publicKeyHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH, BufferManager.NOT_APDU_BUFFER);
        final short publicKeyOffset = bufferManager.getOffsetForHandle(publicKeyHandle);
        final byte[] publicKeyBuffer = bufferManager.getBufferForHandle(apdu, publicKeyHandle);
        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);

        Util.arrayCopyNonAtomic(reqBuffer, readOffset,
                scratchClientDataHashBuffer, scratchClientDataHashOffset, CLIENT_DATA_HASH_LEN);
        readOffset += CLIENT_DATA_HASH_LEN;
        Util.arrayCopyNonAtomic(reqBuffer, readOffset,
                scratchRPIDHashBuffer, scratchRPIDHashOffset, RP_HASH_LEN);

        // Out of the APDU buffer; it's all free!
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

        // Create key pair
        P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
        if (!makeGoodKeyPair(ecKeyPair, publicKeyBuffer, publicKeyOffset)) {
            throwException(ISO7816.SW_DATA_INVALID);
        }

        encodeCredentialID(apdu, (ECPrivateKey) ecKeyPair.getPrivate(),
                scratchRPIDHashBuffer, scratchRPIDHashOffset,
                scratchCredBuffer, scratchCredOffset,
                (short) -1, true, (byte) 0);

        // Generate signature first. Use bufMem as working space
        final short baseAdOffset = 512;
        short adOffset = baseAdOffset;
        final byte[] adBuffer = bufferMem;
        adBuffer[adOffset++] = 0x00; // Fixed magic byte
        adOffset = Util.arrayCopyNonAtomic(scratchRPIDHashBuffer, scratchRPIDHashOffset,
                adBuffer, adOffset, RP_HASH_LEN);
        adOffset = Util.arrayCopyNonAtomic(scratchClientDataHashBuffer, scratchClientDataHashOffset,
                adBuffer, adOffset, CLIENT_DATA_HASH_LEN);
        adOffset = Util.arrayCopyNonAtomic(scratchCredBuffer, scratchCredOffset,
                adBuffer, adOffset, CREDENTIAL_ID_LEN);
        adOffset = Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                adBuffer, adOffset, PUB_KEY_LENGTH);

        // AD buffer now contains data to be signed
        attester.init(attestationKey, Signature.MODE_SIGN);
        final short sigOffset = (short)(1 + PUB_KEY_LENGTH + 1 + CREDENTIAL_ID_LEN + attCertLen);
        final short sigLength = attester.sign(adBuffer, baseAdOffset, (short)(adOffset - baseAdOffset),
                bufferMem, sigOffset);

        // Done with the input; start writing output!
        short outputLen = 0;
        random.generateData(bufferMem, (short) 0, (short) 1);
        short counterIncAmt = (short)((bufferMem[0] & 0x0E) + 1);
        bufferMem[outputLen++] = 0x05; // magic fixed first byte
        outputLen = Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                bufferMem, outputLen, PUB_KEY_LENGTH);
        bufferMem[outputLen++] = (byte) CREDENTIAL_ID_LEN;

        outputLen = Util.arrayCopyNonAtomic(scratchCredBuffer, scratchCredOffset,
                bufferMem, outputLen, CREDENTIAL_ID_LEN);

        outputLen = Util.arrayCopyNonAtomic(attestationData, attCertStart,
                bufferMem, outputLen, attCertLen);
        if (outputLen != sigOffset) {
            throwException(ISO7816.SW_DATA_INVALID);
        }
        outputLen += sigLength;

        if (!counter.increment(counterIncAmt)) {
            throwException(ISO7816.SW_FILE_FULL);
        }

        doSendResponse(apdu, outputLen);
    }

    /**
     * Streams long responses back to the platform - APDU chaining.
     *
     * @param apdu Request/response context object
     * @param apduBytes APDU buffer to hold outgoing data
     * @param chaining If true, set the APDU outgoing length, and throw an exception to indicate remaining bytes
     * @return true if response delivery is complete
     */
    private boolean streamOutgoingContinuation(APDU apdu, byte[] apduBytes, boolean chaining) {
        // continue outgoing response from buffer
        if (transientStorage.getOutgoingContinuationRemaining() == 0) {
            // Nothing to send here, nothing left.
            return true;
        }

        short outgoingOffset = transientStorage.getOutgoingContinuationOffset();
        short outgoingRemaining = transientStorage.getOutgoingContinuationRemaining();
        final boolean x5c = transientStorage.shouldStreamX5CLater();
        final boolean lbk = transientStorage.shouldStreamLBKLater();
        short remainingValidInBufMem = outgoingRemaining;
        short x5cidx = 0;
        short lbkIdx = 0;
        if (x5c) {
            remainingValidInBufMem = transientStorage.getStoredIdx();
            if (remainingValidInBufMem > outgoingOffset) {
                // We still have some reading from bufmem to do
                remainingValidInBufMem = (short)(remainingValidInBufMem - outgoingOffset);
            } else {
                // We've already moved on to x5c data
                x5cidx = (short)(outgoingOffset - remainingValidInBufMem);
                remainingValidInBufMem = (short) 0;

                if (x5cidx > attestationData.length) {
                    lbkIdx = (short)(x5cidx - attestationData.length);
                    x5cidx = (short) attestationData.length;
                }
            }
        }

        short chunkSize = (short)(APDU.getOutBlockSize() - 2);
        if (chaining) {
            final short requestedChunkSize = apdu.setOutgoing();
            if (requestedChunkSize < chunkSize) {
                chunkSize = requestedChunkSize;
            }
        }

        final short writeSize = chunkSize <= outgoingRemaining ? chunkSize : outgoingRemaining;
        if (chaining) {
            apdu.setOutgoingLength(writeSize);
        }
        short chunkToWrite = writeSize;
        if (remainingValidInBufMem > 0) {
            short writeFromBufMem = remainingValidInBufMem;
            if (writeFromBufMem > chunkToWrite) {
                writeFromBufMem = chunkToWrite;
            }
            Util.arrayCopyNonAtomic(bufferMem, outgoingOffset,
                    apduBytes, (short) 0, writeFromBufMem);
            chunkToWrite -= writeFromBufMem;
        }
        if (x5c && chunkToWrite > 0) {
            short x5crem = (short)(attestationData.length - x5cidx);
            if (x5crem > chunkToWrite) {
                x5crem = chunkToWrite;
            }
            Util.arrayCopyNonAtomic(attestationData, x5cidx,
                    apduBytes, remainingValidInBufMem, x5crem);
            chunkToWrite -= x5crem;
            if (lbk && chunkToWrite > 0) {
                Util.arrayCopyNonAtomic(bufferMem, (short)(bufferMem.length - 36 + lbkIdx),
                        apduBytes, (short)(remainingValidInBufMem + x5crem), chunkToWrite);
            }
        }
        apdu.sendBytes((short) 0, writeSize);
        outgoingOffset += writeSize;
        outgoingRemaining -= writeSize;
        transientStorage.setOutgoingContinuation(outgoingOffset, outgoingRemaining);
        if (chaining) {
            if (outgoingRemaining >= 256) {
                throwException(ISO7816.SW_BYTES_REMAINING_00);
            } else if (outgoingRemaining > 0) {
                throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + outgoingRemaining));
            }
            transientStorage.clearOutgoingContinuation();
        }
        return false;
    }

    /**
     * Handles an ISO applet selection command
     *
     * @param apdu Request/response context object
     */
    private void handleAppletSelect(APDU apdu) {
        apdu.setIncomingAndReceive();

        if (apdu.getIncomingLength() < AID.length || Util.arrayCompare(AID, (short) 0,
                apdu.getBuffer(), apdu.getOffsetCdata(), (short) AID.length) != 0) {
            throwException(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (bufferManager == null) {
            // There also might not be enough RAM, quite, if we allocate this during install while the app install
            // parameters array is held in memory...
            initTransientStorage(apdu);

            short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            final short transientMem = availableMem >= MAX_RAM_SCRATCH_SIZE ? MAX_RAM_SCRATCH_SIZE : availableMem;

            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                bufferManager = new BufferManager(transientMem, FLASH_SCRATCH_SIZE);

                bufferManager.initializeAPDU(apdu);

                // ... aaand finally, the actual wrapping key, which we didn't init because we use the above buffers
                resetWrappingKeys(apdu);
                ok = true;
            } finally {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        }

        bufferManager.clear();

        // For U2F compatibility, the CTAP2 standard requires that we respond to select() as if we were a U2F
        // authenticator, and then let the platform figure out we're really CTAP2 by making a getAuthenticatorInfo
        // API request afterwards
        if (alwaysUv || attestationData == null || filledAttestationData < attestationData.length) {
            // ... but we DON'T implement U2F with alwaysUv, so we can send the CTAP2-only response type
            sendByteArray(apdu, CannedCBOR.FIDO_2_RESPONSE, (short) CannedCBOR.FIDO_2_RESPONSE.length);
        } else {
            sendByteArray(apdu, CannedCBOR.U2F_V2_RESPONSE, (short) CannedCBOR.U2F_V2_RESPONSE.length);
        }
    }

    /**
     * Handles an authenticator config CTAP2.1 subcommand
     *
     * @param apdu Request/response object
     * @param reqBuffer Buffer containing incoming request
     * @param lc Length of incoming request, as sent by the platform
     */
    private void authenticatorConfigSubcommand(APDU apdu, byte[] reqBuffer, short lc) {
        short readIdx = (short) 1;

        if (lc < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short numOptions = getMapEntryCount(apdu, reqBuffer[readIdx++]);
        if (numOptions < 1) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        if (reqBuffer[readIdx++] != 0x01) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short cmdByteIdx = readIdx++;
        short cmdParamsIdx = -1;
        short cmdParamsLen = 0;
        short authIndex = -1;

        byte pinProtocol = 1;

        for (short i = 1; i < numOptions; i++) {
            switch (reqBuffer[readIdx++]) {
                case 0x02: // map key: subCommandParams
                    cmdParamsIdx = readIdx;
                    readIdx = consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    cmdParamsLen = (short)(readIdx - cmdParamsIdx);
                    break;
                case 0x03: // map key: pinUvAuthProtocol
                    pinProtocol = reqBuffer[readIdx++];
                    checkPinProtocolSupported(apdu, pinProtocol);
                    break;
                case 0x04: // map key: pinUvAuthParam
                    if (pinProtocol == 1) {
                        if (reqBuffer[readIdx++] != 0x50) { // byte array, 16 bytes long
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        }
                    } else {
                        if (reqBuffer[readIdx++] != 0x58) { // byte array, one-byte length
                            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        }
                        if (reqBuffer[readIdx++] != 0x20) { // 32 bytes long
                            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
                        }
                    }
                    authIndex = readIdx;
                    break;
                default:
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }
        }

        if (pinSet || alwaysUv) {
            if (authIndex == -1) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
            }
            if ((transientStorage.getPinPermissions() & FIDOConstants.PERM_AUTH_CONFIG) == 0x00) {
                // PIN token doesn't have appropriate permissions for authenticator config
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            }

            // Create verification buffer
            final short bufferSize = (short)(32 + cmdParamsLen + 1 + 1);
            final short scratchHandle = bufferManager.allocate(apdu, bufferSize, BufferManager.ANYWHERE);
            final byte[] scratchBuffer = bufferManager.getBufferForHandle(apdu, scratchHandle);
            final short scratchOffset = bufferManager.getOffsetForHandle(scratchHandle);
            Util.arrayFillNonAtomic(scratchBuffer, scratchOffset, (short) 32, (byte) 0xFF);
            scratchBuffer[(short)(scratchOffset + 32)] = 0x0D;
            scratchBuffer[(short)(scratchOffset + 33)] = reqBuffer[cmdByteIdx];
            if (cmdParamsLen > 0) {
                Util.arrayCopyNonAtomic(reqBuffer, cmdParamsIdx,
                        scratchBuffer, (short)(scratchOffset + 34), cmdParamsLen);
            }

            checkPinToken(apdu, scratchBuffer, scratchOffset, bufferSize,
                    reqBuffer, authIndex, pinProtocol, true);

            if (WRITES_INVALIDATE_PINS) {
                transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
            }

            // Whew, done.
            bufferManager.release(apdu, scratchHandle, bufferSize);
        }

        // Rewind to the command byte
        readIdx = cmdByteIdx;

        switch (reqBuffer[readIdx++]) {
            case FIDOConstants.AUTH_CONFIG_ENABLE_ENTERPRISE_ATTESTATION:
                // This does nothing anyway
                enterpriseAttestation = !enterpriseAttestation;
                apdu.getBuffer()[0] = FIDOConstants.CTAP2_OK;
                sendNoCopy(apdu, (short) 1);
                break;
            case FIDOConstants.AUTH_CONFIG_SET_MIN_PIN_LENGTH:
                setMinPin(apdu, reqBuffer, cmdParamsIdx, cmdParamsLen, lc);
                break;
            case FIDOConstants.AUTH_CONFIG_TOGGLE_ALWAYS_UV:
                toggleAlwaysUv(apdu);
                break;
            default:
                // Spec says this is INVALID_PARAMETER, not CTAP2 INVALID_SUBCOMMAND
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                break;
        }
    }

    /**
     * Sets the minimum allowable PIN length
     *
     * @param apdu         Request/response context object
     * @param buffer       Incoming request buffer
     * @param readIdx      Index of command arguments in request buffer
     * @param cmdParamsLen Length of command options
     * @param lc           Incoming request total length
     */
    private void setMinPin(APDU apdu, byte[] buffer, short readIdx, short cmdParamsLen, short lc) {
        if (cmdParamsLen == 0) {
            // This is technically a fine command, but it does nothing
            apdu.getBuffer()[0] = FIDOConstants.CTAP2_OK;
            sendNoCopy(apdu, (short) 1);
            return;
        }

        byte newMinPINLength = minPinLength;
        boolean newForceChangePIN = false;
        short rpIDIdx = -1;
        byte numRPIDs = 0;

        short numEntries = getMapEntryCount(apdu, buffer[readIdx++]);
        for (short i = 0; i < numEntries; i++) {
            switch (buffer[readIdx++]) {
                case 0x01: // newMinPinLength
                    byte lenByte = buffer[readIdx++];
                    if (lenByte == 0x18) {
                        newMinPINLength = buffer[readIdx++];
                    } else if (lenByte < 0x18) {
                        newMinPINLength = lenByte;
                    } else {
                        sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    break;
                case 0x02: // minPinLengthRPIDs
                    byte plRIPByte = buffer[readIdx];
                    if (ub(plRIPByte) < 0x80 || ub(plRIPByte) > 0x97) {
                        // empty array
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                    }
                    numRPIDs = (byte)(ub(plRIPByte) - 0x80);
                    if (numRPIDs > MAX_RP_IDS_MIN_PIN_LENGTH) { // empty array
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
                    }
                    rpIDIdx = (short)(readIdx + 1);
                    readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                    if (readIdx > lc) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                    }
                    break;
                case 0x03: // forceChangePIN
                    switch (buffer[readIdx++]) {
                        case (byte) 0xF4: // false
                            break; // nothing to do here
                        case (byte) 0xF5: // true
                            newForceChangePIN = true;
                            break;
                        default:
                            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
                    }
                    break;
                default:
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }
        }

        if (newMinPINLength < minPinLength) {
            // min PIN can go up but not down
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        if (newMinPINLength > 63) {
            // not a great idea.
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        if (!pinSet && newForceChangePIN) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            if (STORE_PIN_LENGTH) {
                if (pinSet && newMinPINLength > pinCodePointLength) {
                    forcePinChange = true; // current PIN is inadequately long
                }
            } else if (newMinPINLength > minPinLength && pinSet) {
                forcePinChange = true; // ALWAYS force a PIN change because we don't know the PIN length
            }
            minPinLength = newMinPINLength;
            if (!forcePinChange) {
                forcePinChange = newForceChangePIN;
            }

            short readOffset = rpIDIdx;
            short i = 0;
            for (; i < numRPIDs; i++) {
                short rpIdLen = 0;
                if (buffer[readOffset] == 0x78) { // string with one-byte length
                    rpIdLen = ub(buffer[++readOffset]);
                    readOffset++;
                } else if (buffer[readOffset] >= 0x60 && buffer[readOffset] <= 0x77) {
                    rpIdLen = (short)(buffer[readOffset] - 0x60);
                    readOffset++;
                } else {
                    // aborting the transaction...
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                sha256.doFinal(buffer, readOffset, rpIdLen,
                        minPinRPIDs, (short)(i * RP_HASH_LEN));
            }
            for (; i < MAX_RP_IDS_MIN_PIN_LENGTH; i++) {
                Util.arrayFillNonAtomic(minPinRPIDs, (short)(i * RP_HASH_LEN), RP_HASH_LEN, (byte) 0x00);
            }

            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        apdu.getBuffer()[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Toggle the state of the alwaysUv (require User Verification) option
     *
     * @param apdu Request/response context object
     */
    private void toggleAlwaysUv(APDU apdu) {
        if (FORCE_ALWAYS_UV) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
        }
        alwaysUv = !alwaysUv;

        apdu.getBuffer()[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Handles an authenticatorSelection FIDO2 command
     *
     * @param apdu Request/response object
     */
    private void authenticatorSelection(APDU apdu) {
        // Presence not really implemented - user always considered present
        final byte[] buffer = apdu.getBuffer();

        buffer[0] = FIDOConstants.CTAP2_OK;

        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Handler to consume and dispatch subcommands for the credential management optional feature
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param lc Length of incoming request, as sent by the platform
     */
    private void credManagementSubcommand(APDU apdu, byte[] buffer, short lc) {
        short readIdx = 1;

        if (resetRequested) {
            resetRequested = false;
        }

        if (!pinSet) {
            // All credential management commands require and validate a PIN
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        final short numOptions = getMapEntryCount(apdu, buffer[readIdx++]);

        if (buffer[readIdx++] != 0x01) { // map key: subCommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        final short subCommandIdx = readIdx;
        final short subCommandNumber = ub(buffer[readIdx++]);
        if (subCommandNumber > 23) {
            // This will likely never be legal...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short subCommandParamsIdx = -1;
        short subCommandParamsLen = 0;
        if (buffer[readIdx] == 0x02) { // map key: subCommandParams
            subCommandParamsIdx = ++readIdx;
            readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            subCommandParamsLen = (short)(readIdx - subCommandParamsIdx);
        }

        if (subCommandNumber != FIDOConstants.CRED_MGMT_ENUMERATE_RPS_NEXT &&
            subCommandNumber != FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_NEXT) {
            // Don't ask me why these commands don't need the PIN token...
            if (buffer[readIdx++] != 0x03) { // map key: pinUvAuthProtocol
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            byte pinProtocol = buffer[readIdx++];
            checkPinProtocolSupported(apdu, pinProtocol);

            if (buffer[readIdx++] != 0x04) { // map key: pinUvAuthParam
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (pinProtocol == 1) {
                if (buffer[readIdx++] != 0x50) { // byte array, 16 bytes long
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            } else {
                if (buffer[readIdx++] != 0x58) { // byte array, one-byte length
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (buffer[readIdx++] != 0x20) { // 32 bytes long
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
                }
            }

            // Check PIN token
            if ((transientStorage.getPinPermissions() & FIDOConstants.PERM_CRED_MANAGEMENT) == 0x00) {
                // PIN token doesn't have appropriate permissions for credential management operations
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            }
            if (subCommandParamsIdx != -1) {
                // Straight-up mangle the input buffer to put the command byte immediately before the subcommand params
                buffer[(short)(subCommandParamsIdx - 1)] = buffer[subCommandIdx];
                checkPinToken(apdu, buffer, (short) (subCommandParamsIdx - 1), (short) (subCommandParamsLen + 1),
                        buffer, readIdx, pinProtocol, true);
            } else {
                checkPinToken(apdu, buffer, subCommandIdx, (short) 1,
                        buffer, readIdx, pinProtocol, true);
            }
        }

        switch (subCommandNumber) {
            case FIDOConstants.CRED_MGMT_GET_CREDS_META:
                handleCredentialManagementGetCredsMetadata(apdu);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_RPS_BEGIN:
                handleEnumerateRPs(apdu, (short) 0);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_RPS_NEXT:
                short rpPtr = transientStorage.getRPIterationPointer();
                if (rpPtr == 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                }
                handleEnumerateRPs(apdu, rpPtr);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_NEXT:
                short credPtr = transientStorage.getCredIterationPointer();
                if (credPtr == 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                }
                handleEnumerateCreds(apdu, buffer, (short) -1, credPtr, lc);
                break;
            case FIDOConstants.CRED_MGMT_ENUMERATE_CREDS_BEGIN:
                handleEnumerateCreds(apdu, buffer, subCommandParamsIdx, (short) 0, lc);
                break;
            case FIDOConstants.CRED_MGMT_DELETE_CRED:
                handleDeleteCred(apdu, buffer, subCommandParamsIdx, lc);
                if (WRITES_INVALIDATE_PINS) {
                    transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
                }
                break;
            case FIDOConstants.CRED_MGMT_UPDATE_USER_INFO:
                handleUserUpdate(apdu, buffer, subCommandParamsIdx, lc);
                if (WRITES_INVALIDATE_PINS) {
                    transientStorage.setPinProtocolInUse((byte) 3, (byte) 0);
                }
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                break;
        }
    }

    /**
     * Handles a CTAP credential management user update subcommand
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readOffset Index of subcommand parameters in read buffer
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleUserUpdate(APDU apdu, byte[] buffer, short readOffset, short lc) {
        if (buffer[readOffset++] != (byte) 0xA2) { // map with two entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (buffer[readOffset++] != 0x02) { // map key: credentialId
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readOffset = consumeMapAndGetID(apdu, buffer, readOffset, lc, true, true, false, false);
        final short credIdIdx = transientStorage.getStoredIdx();
        final short credIdLen = transientStorage.getStoredLen();
        if (credIdLen != CREDENTIAL_ID_LEN) {
            // Not our credential - can't match anything
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        if (buffer[readOffset++] != 0x03) { // map key: user
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        final short userMapOffset = readOffset;
        readOffset = consumeMapAndGetID(apdu, buffer, readOffset, lc, true, false, true, false);
        if (readOffset > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        final short userIdIdx = transientStorage.getStoredIdx();
        final byte userIdLen = transientStorage.getStoredLen();
        if (userIdLen > MAX_USER_ID_LENGTH) {
            // We can't store user IDs this long, so we won't have one stored...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        consumeMapAndGetID(apdu, buffer, userMapOffset, lc, false, false, false, true);
        final short userNameIdx = transientStorage.getStoredIdx();
        final byte userNameLen = transientStorage.getStoredLen();

        boolean foundHit = false;
        for (short i = 0; i < (short) residentKeys.length; i++) {
            if (residentKeys[i] == null) {
                break;
            }

            // Don't need to decrypt creds, just byte-compare them
            if (Util.arrayCompare(residentKeys[i].getEncryptedCredentialID(), (short) 0,
                    buffer, credIdIdx, CREDENTIAL_ID_LEN) == 0) {
                // Matching cred.
                // We need to extract the credential to check that our PIN token WOULD have permission
                if (permissionsRpId[0] != 0x00) {
                    short scratchExtractedCredHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.ANYWHERE);
                    short scratchExtractedCredOffset = bufferManager.getOffsetForHandle(scratchExtractedCredHandle);
                    byte[] scratchExtractedCredBuffer = bufferManager.getBufferForHandle(apdu, scratchExtractedCredHandle);
                    if (!checkCredential(
                            apdu, i,
                            permissionsRpId, (short) 1,
                            scratchExtractedCredBuffer, scratchExtractedCredOffset, (byte) 3
                    )) {
                        // permissions RP ID in use, but doesn't match RP of this credential
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                    bufferManager.release(apdu, scratchExtractedCredHandle, CREDENTIAL_PAYLOAD_LEN);
                }

                // If we're here, it's time to update the user info for the stored cred
                foundHit = true;
                JCSystem.beginTransaction();
                boolean ok = false;
                try {
                    residentKeys[i].setUser(getAESKeyForExistingRK(i), symmetricWrapper,
                            buffer, userIdIdx, userIdLen,
                            buffer, userNameIdx, userNameLen);
                    ok = true;
                } finally {
                    if (ok) {
                        JCSystem.commitTransaction();
                    } else {
                        JCSystem.abortTransaction();
                    }
                }
                try {
                    JCSystem.requestObjectDeletion();
                } catch (Exception e) {
                    // No real problem, I guess
                }
                break;
            }
        }

        if (!foundHit) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        final byte[] outBuf = apdu.getBuffer();
        outBuf[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Deletes a resident key by its credential ID blob, and updates bookkeeping state to match
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readOffset Read index into input buffer
     * @param lc Length of incoming request, as sent by the platform
     */
    private void handleDeleteCred(APDU apdu, byte[] buffer, short readOffset, short lc) {
        transientStorage.clearIterationPointers();

        if (buffer[readOffset++] != (byte) 0xA1) { // map with one entry
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (buffer[readOffset++] != 0x02) { // map key: credentialId
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readOffset = consumeMapAndGetID(apdu, buffer, readOffset, lc, true, true, false, false);
        if (readOffset > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        final short credIdIdx = transientStorage.getStoredIdx();
        final short credIdLen = transientStorage.getStoredLen();

        byte[] outBuf = apdu.getBuffer();
        if (credIdLen != CREDENTIAL_ID_LEN) {
            // We're not gonna have credentials of random lengths on here...
            outBuf[0] = FIDOConstants.CTAP2_OK;
            sendNoCopy(apdu, (short) 1);
            return;
        }

        for (short i = 0; i < (short) residentKeys.length; i++) {
            if (residentKeys[i] == null) {
                break;
            }

            // Compare still encrypted, which is fine
            if (Util.arrayCompare(residentKeys[i].getEncryptedCredentialID(), (short) 0,
                    buffer, credIdIdx, residentKeys[i].getCredLen()) == 0) {
                // Found a match! Unfortunately, we need to unpack the credential to check if this PIN token
                // has permission to delete it...

                final short mainCredHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.NOT_LOWER_APDU);
                final short mainCredIdx = bufferManager.getOffsetForHandle(mainCredHandle);
                final byte[] mainCredBuffer = bufferManager.getBufferForHandle(apdu, mainCredHandle);

                extractRKMixed(buffer, credIdIdx, mainCredBuffer, mainCredIdx, i);
                final short rpIdHashIdx = mainCredIdx;

                if (permissionsRpId[0] != 0x00) {
                    if (Util.arrayCompare(outBuf, rpIdHashIdx,
                            permissionsRpId, (short) 1, RP_HASH_LEN) != 0) {
                        // permissions RP ID in use, but doesn't match RP of deleteCred operation
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }

                if (residentKeys[i].isUniqueRP()) {
                    // Due to how we manage RP validity, we need to find ANOTHER RK with the same RP,
                    // to set the unique-RP bit on it and thus "promote" it to being the representative
                    // of the RP for iteration purposes
                    short rpHavingSameRP = -1;

                    final short secondCredHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.NOT_LOWER_APDU);
                    final short secondCredIdx = bufferManager.getOffsetForHandle(secondCredHandle);
                    final byte[] secondCredBuffer = bufferManager.getBufferForHandle(apdu, secondCredHandle);

                    for (short otherRKIdx = 0; otherRKIdx < (short) residentKeys.length; otherRKIdx++) {
                        if (otherRKIdx == i) {
                            // we want ANOTHER RK, not this one...
                            continue;
                        }
                        if (residentKeys[otherRKIdx] == null) {
                            // oops, hit the end
                            break;
                        }
                        if (checkCredential(apdu, otherRKIdx,
                                mainCredBuffer, rpIdHashIdx,
                                secondCredBuffer, secondCredIdx, (byte) 3)) {
                            // match. this is our promotion candidate!
                            rpHavingSameRP = otherRKIdx;
                            break;
                        }
                    }

                    bufferManager.release(apdu, secondCredHandle, CREDENTIAL_PAYLOAD_LEN);

                    JCSystem.beginTransaction();
                    boolean ok = false;
                    try {
                        if (rpHavingSameRP == -1) {
                            // We couldn't find anybody else that shared our RP, which means deleting us
                            // also lowered the total RP count by one
                            numResidentRPs--;
                        } else {
                            residentKeys[rpHavingSameRP].setUniqueRP(true);
                        }
                        for (short j = i; j < (short)(numResidentCredentials - 1); j++) {
                            residentKeys[j] = residentKeys[(short)(j + 1)];
                        }
                        residentKeys[--numResidentCredentials] = null;
                        ok = true;
                    } finally {
                        if (ok) {
                            JCSystem.commitTransaction();
                        } else {
                            JCSystem.abortTransaction();
                        }
                    }
                } else {
                    JCSystem.beginTransaction();
                    boolean ok = false;
                    try {
                        for (short j = i; j < (short)(numResidentCredentials - 1); j++) {
                            residentKeys[j] = residentKeys[(short)(j + 1)];
                        }
                        residentKeys[--numResidentCredentials] = null;
                        ok = true;
                    } finally {
                        if (ok) {
                            JCSystem.commitTransaction();
                        } else {
                            JCSystem.abortTransaction();
                        }
                    }
                }

                bufferManager.release(apdu, mainCredHandle, CREDENTIAL_PAYLOAD_LEN);

                break;
            }
        }

        // If we got here, we might not have found a matching credential. That's okay.
        outBuf[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Enumerates creds
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param bufferIdx Read index into input buffer
     * @param startCredIdx Offset of the first credential to consider, in the resident key slots.
     *                     If zero, we're starting a new iteration
     * @param lc Length of the incoming request, as sent by the platform
     */
    private void handleEnumerateCreds(APDU apdu, byte[] buffer, short bufferIdx, short startCredIdx, short lc) {
        transientStorage.clearIterationPointers();

        if (startCredIdx > (short) residentKeys.length) { // intentional > instead of >=
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        // We are only going to pull exactly one more piece of information out of the APDU buffer, so it's okay
        // if our scratch allocation comes from it
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

        final short rpIdHashHandle = bufferManager.allocate(apdu, (short)(CREDENTIAL_ID_LEN + RP_HASH_LEN), BufferManager.ANYWHERE);
        final byte[] rpIdHashBuf = bufferManager.getBufferForHandle(apdu, rpIdHashHandle);
        short rpIdHashIdx = bufferManager.getOffsetForHandle(rpIdHashHandle);
        short credIdIdx = (short)(rpIdHashIdx + RP_HASH_LEN);
        if (startCredIdx == 0) {
            // Iteration start: read RP ID hash from request buffer
            if (buffer[bufferIdx++] != (byte) 0xA1) { // map, one entry
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (buffer[bufferIdx++] != 0x01) { // map key: rpIdHash
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (buffer[bufferIdx++] != 0x58 || buffer[bufferIdx++] != RP_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

            if ((short)(bufferIdx + RP_HASH_LEN) >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }

            Util.arrayCopyNonAtomic(buffer, bufferIdx,
                    rpIdHashBuf, rpIdHashIdx, RP_HASH_LEN);

            if (permissionsRpId[0] != 0x00) {
                // A permissions RP ID is set: verify it matches the RP for which we're iterating creds
                if (Util.arrayCompare(rpIdHashBuf, rpIdHashIdx,
                        permissionsRpId, (short) 1, RP_HASH_LEN) != 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
        } else {
            // Continuing iteration, we get the RP ID hash from the previous credential
            final short iterIdx = (short)(startCredIdx - 1);
            extractRKMixed(residentKeys[iterIdx].getEncryptedCredentialID(), (short) 0,
                    rpIdHashBuf, rpIdHashIdx, iterIdx);
        }

        short rkIndex;
        for (rkIndex = startCredIdx; rkIndex < (short) residentKeys.length; rkIndex++) {
            if (residentKeys[rkIndex] == null) {
                break;
            }

            if (checkCredential(
                    apdu, rkIndex,
                    rpIdHashBuf, rpIdHashIdx,
                    rpIdHashBuf, credIdIdx, (byte) 3)) {
                // Cred is for this RP ID, yay.

                byte matchingCount = 1; // remember to count THIS cred as a match
                if (startCredIdx == 0) {
                    // Unfortunately, we need to scan forward through all remaining credentials
                    // we're not storing a list of which creds share an RP, so this is the only way to get
                    // the count associated with this RP...
                    for (short otherCredIdx = (short) (rkIndex + 1); otherCredIdx < (short) residentKeys.length; otherCredIdx++) {
                        if (residentKeys[otherCredIdx] == null) {
                            break;
                        }

                        if (checkCredential(
                                apdu, otherCredIdx,
                                rpIdHashBuf, rpIdHashIdx,
                                // okay to clobber decrypted data from other cred; it's unused
                                rpIdHashBuf, credIdIdx, (byte) 3
                        )) {
                            matchingCount++;
                        }
                    }
                }
                transientStorage.setCredIterationPointer((byte)(rkIndex + 1)); // resume iteration from beyond this one

                byte[] outBuf = bufferMem;

                short writeOffset = 0;

                outBuf[writeOffset++] = FIDOConstants.CTAP2_OK;
                outBuf[writeOffset++] = startCredIdx == 0 ? (byte) 0xA5 : (byte) 0xA4; // map, four or five entries
                outBuf[writeOffset++] = 0x06; // map key: pubKeyCredentialsUserEntry
                final short userNameLength = residentKeys[rkIndex].getUserNameLength();

                final byte[] preamble = userNameLength > 0 ? CannedCBOR.ID_AND_NAME_MAP_PREAMBLE : CannedCBOR.SINGLE_ID_MAP_PREAMBLE;
                writeOffset = Util.arrayCopyNonAtomic(preamble, (short) 0,
                        outBuf, writeOffset, (short) preamble.length);

                final short userIdLength = residentKeys[rkIndex].getUserIdLength();
                writeOffset = encodeIntLenTo(outBuf, writeOffset, userIdLength, true);

                AESKey key = getAESKeyForExistingRK(rkIndex);

                // The user ID needs to be fully decrypted (MAX_USER_ID_LENGTH bytes)
                residentKeys[rkIndex].unpackUserID(key, symmetricUnwrapper,
                        outBuf, writeOffset);
                // ... but we only advance the write offset by however many bytes of it are really valid
                writeOffset += userIdLength;

                if (userNameLength > 0) {
                    writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.NAME, (short) 0,
                            outBuf, writeOffset, (short) CannedCBOR.NAME.length);
                    writeOffset = encodeIntLenTo(outBuf, writeOffset, userNameLength, false);
                    residentKeys[rkIndex].unpackUserName(key, symmetricUnwrapper,
                            outBuf, writeOffset);
                    writeOffset += userNameLength;
                }

                outBuf[writeOffset++] = 0x07; // map key: credentialId
                writeOffset = packCredentialId(residentKeys[rkIndex].getEncryptedCredentialID(), (short) 0,
                        outBuf, writeOffset);

                outBuf[writeOffset++] = 0x08; // map key: publicKey
                writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE, (short) 0,
                        outBuf, writeOffset, (short) CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE.length);

                short pkBufHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH, BufferManager.ANYWHERE);
                byte[] pkBuf = bufferManager.getBufferForHandle(apdu, pkBufHandle);
                short pkBufIdx = bufferManager.getOffsetForHandle(pkBufHandle);

                residentKeys[rkIndex].unpackPublicKey(
                        pkBuf, pkBufIdx);
                writeOffset = writePubKey(outBuf, writeOffset, pkBuf, pkBufIdx);

                bufferManager.release(apdu, pkBufHandle, PUB_KEY_LENGTH);

                if (startCredIdx == 0) {
                    outBuf[writeOffset++] = 0x09; // map key: totalCredentials
                    writeOffset = encodeIntTo(outBuf, writeOffset, matchingCount);
                }

                outBuf[writeOffset++] = 0x0A; // map key: credProtect
                outBuf[writeOffset++] = residentKeys[rkIndex].getCredProtectLevel();

                doSendResponse(apdu, writeOffset);
                return;
            }
        }

        // If we fall through to here, we didn't find a cred
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
    }

    /**
     * Pack a credential ID (CBOR-wrapped) into a target buffer
     *
     * @param credBuffer Buffer containing credential ID
     * @param credOffset Offset of credential ID in input buffer
     * @param writeBuffer Output buffer into which to write CBOR
     * @param writeOffset Write index into output buffer
     *
     * @return New write index into output buffer, after writing credential CBOR
     */
    private short packCredentialId(byte[] credBuffer, short credOffset, byte[] writeBuffer, short writeOffset) {
        writeBuffer[writeOffset++] = (byte) 0xA2; // map: two entries

        writeBuffer[writeOffset++] = 0x62; // string - two bytes long
        writeBuffer[writeOffset++] = 0x69; // i
        writeBuffer[writeOffset++] = 0x64; // d
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, CREDENTIAL_ID_LEN, true);
        writeOffset = Util.arrayCopyNonAtomic(credBuffer, credOffset,
                writeBuffer, writeOffset, CREDENTIAL_ID_LEN);

        writeBuffer[writeOffset++] = 0x64; // string - four bytes long
        writeBuffer[writeOffset++] = 0x74; // t
        writeBuffer[writeOffset++] = 0x79; // y
        writeBuffer[writeOffset++] = 0x70; // p
        writeBuffer[writeOffset++] = 0x65; // e
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length, false);
        writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_TYPE, (short) 0,
                writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length);

        return writeOffset;
    }

    /**
     * We can create credentials with incorrect "unique RP" flags if:
     * 1. we create a high-security RK
     * 2. we create a low-security RK from the same RP, when the PIN isn't provided
     * So we might have some keys which are incorrectly flagged as being from unique RPs...
     * This method goes through and fixes those. It should only be called when the
     * high-security key is available for use.
     * This is, unfortunately, O(N^2) in the number of unique RPs.
     */
    private void updateRKStatekeeping(APDU apdu) {
        short rp2Handle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.ANYWHERE);
        byte[] rp2Buffer = bufferManager.getBufferForHandle(apdu, rp2Handle);
        short rp2Offset = bufferManager.getOffsetForHandle(rp2Handle);

        short rp1Handle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.ANYWHERE);
        byte[] rp1Buffer = bufferManager.getBufferForHandle(apdu, rp1Handle);
        short rp1Offset = bufferManager.getOffsetForHandle(rp1Handle);

        byte numUniqueRPsFound = 0;

        for (short rkIndex1 = 0; rkIndex1 < (short) residentKeys.length; rkIndex1++) {
            if (residentKeys[rkIndex1] == null) {
                break;
            }
            if (!residentKeys[rkIndex1].isUniqueRP()) {
                // definitely non-unique (or inactive) RP
                continue;
            }
            numUniqueRPsFound++;
            extractRKMixed(residentKeys[rkIndex1].getEncryptedCredentialID(), (short) 0,
                    rp2Buffer, rp2Offset, rkIndex1);
            Util.arrayCopyNonAtomic(rp2Buffer, rp2Offset,
                    rp1Buffer, rp1Offset, RP_HASH_LEN);
            for (short rkIndex2 = (short)(rkIndex1 + 1); rkIndex2 < (short) residentKeys.length; rkIndex2++) {
                if (residentKeys[rkIndex2] == null) {
                    break;
                }
                if (!residentKeys[rkIndex2].isUniqueRP()) {
                    // definitely non-unique RP
                    continue;
                }

                // Two different RPs; compare!
                extractRKMixed(residentKeys[rkIndex2].getEncryptedCredentialID(), (short) 0,
                        rp2Buffer, rp2Offset, rkIndex2);

                if (Util.arrayCompare(rp1Buffer, rp1Offset,
                        rp2Buffer, rp2Offset, RP_HASH_LEN) == 0) {
                    // They're the same picture.
                    // Mark second RPID non-unique
                    residentKeys[rkIndex2].setUniqueRP(false);
                }
            }
        }

        numResidentRPs = numUniqueRPsFound;

        bufferManager.release(apdu, rp1Handle, RP_HASH_LEN);
        bufferManager.release(apdu, rp2Handle, CREDENTIAL_ID_LEN);
    }

    /**
     * Handles enumerating stored RPs on the authenticator
     *
     * @param apdu Request/response offset
     * @param startOffset The index of the next RK which has a "unique" RP
     */
    private void handleEnumerateRPs(APDU apdu, short startOffset) {
        if (permissionsRpId[0] != 0x00) {
            // Standard requires that a PIN token *not* be bound to an RP ID for this subcommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        // if anything goes wrong, iteration will need to be restarted
        transientStorage.clearIterationPointers();

        if (startOffset == 0 && !FORCE_ALWAYS_UV && USE_LOW_SECURITY_FOR_SOME_RKS) {
            // "garbage collect" the RK state-keeping before we start
            // the RK meta-info could be corrupted by creating RKs when the high-security key is unavailable...
            updateRKStatekeeping(apdu);
        }

        short rkIndex;
        for (rkIndex = startOffset; rkIndex < (short) residentKeys.length; rkIndex++) {
            // if a credential is not for a *unique* RP, ignore it - we're enumerating RPs here!
            if (residentKeys[rkIndex] == null) {
                break;
            }
            if (residentKeys[rkIndex].isUniqueRP()) {
                // unique RP - use this one!
                break;
            }
        }

        if (rkIndex >= numResidentCredentials) {
            // Iterated too far, or called with no stored creds...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }

        boolean isContinuation = startOffset > 0;

        short writeOffset = 0;

        byte[] outBuf = apdu.getBuffer();

        outBuf[writeOffset++] = FIDOConstants.CTAP2_OK;

        transientStorage.setRPIterationPointer((byte)(rkIndex + 1));

        outBuf[writeOffset++] = isContinuation ? (byte) 0xA2 : (byte) 0xA3; // map with two or three keys
        outBuf[writeOffset++] = 0x03; // map key: rp
        writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.SINGLE_ID_MAP_PREAMBLE, (short) 0,
                outBuf, writeOffset, (short) CannedCBOR.SINGLE_ID_MAP_PREAMBLE.length);
        byte rpIdLength = residentKeys[rkIndex].getRpIdLength();
        writeOffset = encodeIntLenTo(outBuf, writeOffset, rpIdLength, false);

        // Decrypt the full RP ID, ...
        residentKeys[rkIndex].unpackRpId(getAESKeyForExistingRK(rkIndex), symmetricUnwrapper,
                outBuf, writeOffset);
        // ... but only advance the write cursor by as much of it is valid
        writeOffset += rpIdLength;

        outBuf[writeOffset++] = 0x04; // map key: rpIdHash
        writeOffset = encodeIntLenTo(outBuf, writeOffset, RP_HASH_LEN, true);

        // Unwrap the given RK so we can return its decrypted RP hash
        extractRKMixed(residentKeys[rkIndex].getEncryptedCredentialID(), (short) 0,
                outBuf, writeOffset, rkIndex);
        writeOffset += RP_HASH_LEN;

        if (!isContinuation) {
            outBuf[writeOffset++] = 0x05; // map key: totalRPs
            writeOffset = encodeIntTo(outBuf, writeOffset, numResidentRPs);
        }

        sendNoCopy(apdu, writeOffset);
    }

    /**
     * Gets the AES key used for the data associated with the given RK
     *
     * @param rkIndex Index of the RK in the store
     * @return An AES key object to pass to ResidentKeyData methods
     */
    private AESKey getAESKeyForExistingRK(short rkIndex) {
        if (residentKeys[rkIndex].getHighSecEncrypted()) {
            return highSecurityWrappingKey;
        } else {
            return lowSecurityWrappingKey;
        }
    }

    /**
     * Processes the CTAP2.1 credential management getCredsMetaData command
     *
     * @param apdu Request/response object
     */
    private void handleCredentialManagementGetCredsMetadata(APDU apdu) {
        if (permissionsRpId[0] != 0x00) {
            // Standard requires that a PIN token *not* be bound to an RP ID for this subcommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        short writeOffset = 0;

        byte[] outBuf = apdu.getBuffer();

        outBuf[writeOffset++] = FIDOConstants.CTAP2_OK;
        outBuf[writeOffset++] = (byte) 0xA2; // map: two items
        outBuf[writeOffset++] = 0x01; // map key: existingResidentCredentialsCount
        writeOffset = encodeIntTo(outBuf, writeOffset, numResidentCredentials);
        outBuf[writeOffset++] = 0x02; // map key: maxPossibleRemainingCredentialsCount
        writeOffset = encodeIntTo(outBuf, writeOffset, getApproximateRemainingKeyCount());

        sendNoCopy(apdu, writeOffset);
    }

    /**
     * Packs a low-valued integer as a CBOR value into a given buffer
     *
     * @param outBuf Buffer into which to write
     * @param writeOffset Write offset into given buffer
     * @param v Value to pack
     *
     * @return New write offset into given buffer
     */
    private short encodeIntTo(byte[] outBuf, short writeOffset, byte v) {
        if (v < 24) {
            outBuf[writeOffset++] = v;
        } else {
            outBuf[writeOffset++] = 0x18; // Integer stored in one byte
            outBuf[writeOffset++] = v;
        }
        return writeOffset;
    }

    /**
     * Reset authenticator to factory fresh state
     *
     * @param apdu Request/response object
     */
    private void authenticatorReset(APDU apdu) {
        if (PROTECT_AGAINST_MALICIOUS_RESETS) {
            if (transientStorage.isResetCommandSentSincePowerOn()) {
                // Already tried to reset once since power applied, and the protection feature is enabled.
                // Power off the token before trying again.
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
            }

            if (!resetRequested) {
                // Reject this request, to require confirmation
                transientStorage.setResetCommandSentSincePowerOn();
                resetRequested = true;
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
            }
        }

        final short pinIdx = pinRetryCounter.prepareIndex();
        final byte tempBlobStoreIndex = (byte)(largeBlobStoreIndex == 0 ? 1 : 0);

        // Empty the large blob store OUTside the main transaction, since it's non-precious and double buffered
        final byte[] inactiveLargeBlobStore = getInactiveLargeBlobStore();
        final byte[] activeLargeBlobStore = getCurrentLargeBlobStore();
        Util.arrayFillNonAtomic(inactiveLargeBlobStore, (short) 0,
                (short) inactiveLargeBlobStore.length, (byte) 0x00);
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0,
                inactiveLargeBlobStore, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);
        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            largeBlobStoreIndex = tempBlobStoreIndex;
            largeBlobStoreFill = (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length;
            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }
        // active is now inactive
        Util.arrayFillNonAtomic(activeLargeBlobStore, (short) 0,
                (short) activeLargeBlobStore.length, (byte) 0x00);
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0,
                activeLargeBlobStore, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);

        JCSystem.beginTransaction();
        ok = false;
        try {
            random.generateData(hmacWrapperBytesUV, (short) 0, (short) hmacWrapperBytesUV.length);
            random.generateData(hmacWrapperBytesNoUV, (short) 0, (short) hmacWrapperBytesNoUV.length);
            random.generateData(credentialVerificationKey, (short) 0, (short) credentialVerificationKey.length);

            residentKeys = new ResidentKeyData[NUM_RESIDENT_KEY_SLOTS_PER_BATCH];
            numResidentCredentials = 0;
            numResidentRPs = 0;

            pinSet = false;
            if (STORE_PIN_LENGTH) {
                pinCodePointLength = 0;
            }
            minPinLength = 4;
            forcePinChange = false;
            alwaysUv = FORCE_ALWAYS_UV;
            enterpriseAttestation = false;
            pinRetryCounter.reset(pinIdx);
            Util.arrayFillNonAtomic(minPinRPIDs, (short) 0, (short) (MAX_RP_IDS_MIN_PIN_LENGTH * RP_HASH_LEN), (byte) 0x00);

            random.generateData(pinKDFSalt, (short) 0, (short) pinKDFSalt.length);
            random.generateData(highSecurityWrappingIV, (short) 0, (short) highSecurityWrappingIV.length);

            resetWrappingKeys(apdu);

            counter.clear();

            transientStorage.fullyReset();

            forceInitKeyAgreementKey();

            resetRequested = false;

            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
                sendErrorByte(apdu, FIDOConstants.CTAP2_OK);
            } else {
                JCSystem.abortTransaction();
                throwException(ISO7816.SW_DATA_INVALID);
            }
        }

        try {
            JCSystem.requestObjectDeletion();
        } catch (Exception e) {
            // No problem, really
        }
    }

    /**
     * Resets the "wrapping keys" to a random value. THIS INVALIDATES ALL ISSUED CREDENTIALS.
     *
     * After call, symmetric crypto is available with the new (random) key.
     *
     * @param apdu Request/response object
     */
    private void resetWrappingKeys(APDU apdu) {
        random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
        lowSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);

        random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
        highSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
        random.generateData(wrappingKeyValidation, (short) 0, (short) 32);

        // Put the HMAC-SHA256 of the first half of wrappingKeyValidation into the second half
        // We'll use this to validate we have the correct wrapping key
        hmacSha256(apdu, wrappingKeySpace, (short) 0,
                wrappingKeyValidation, (short) 0, (short) 32,
                wrappingKeyValidation, (short) 32);
    }

    /**
     * Replies to the FIDO2 authenticator info command
     *
     * @param apdu Request/response object
     */
    private void sendAuthInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        boolean longResponse = apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA;

        short offset = 0;

        short numOptions = 0x00B0;
        boolean includeMaxMsgSize = bufferMem.length != 1024;
        boolean includeCertifications = CERTIFICATION_LEVEL > 0;
        if (includeMaxMsgSize) {
            numOptions++;
        }
        if (includeCertifications) {
            numOptions++;
        }

        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) numOptions; // Map - some number of options
        buffer[offset++] = 0x01; // map key: versions

        if (alwaysUv || attestationData == null || filledAttestationData < attestationData.length) {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITHOUT_U2F, (short) 0,
                    buffer, offset, (short) CannedCBOR.VERSIONS_WITHOUT_U2F.length);
        } else {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITH_U2F, (short) 0,
                    buffer, offset, (short) CannedCBOR.VERSIONS_WITH_U2F.length);
        }

        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_START, (short) 0,
                buffer, offset, (short) CannedCBOR.AUTH_INFO_START.length);

        offset = Util.arrayCopyNonAtomic(aaguid, (short) 0,
                buffer, offset, (short) aaguid.length);

        buffer[offset++] = 0x04; // map key: options
        buffer[offset++] = (byte) 0xAB; // map: eleven entries
        /*buffer[offset++] = 0x62; // string: two bytes long
        buffer[offset++] = 0x65; // 'e'
        buffer[offset++] = 0x70; // 'p'
        buffer[offset++] = (byte)(enterpriseAttestation ? 0xF5 : 0xF4); // enabled or not */

        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_SECOND, (short) 0,
                buffer, offset, (short) CannedCBOR.AUTH_INFO_SECOND.length);

        buffer[offset++] = (byte)(alwaysUv ? 0xF5 : 0xF4); // alwaysUv

        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_THIRD, (short) 0,
                buffer, offset, (short) CannedCBOR.AUTH_INFO_THIRD.length);

        buffer[offset++] = (byte)(pinSet ? 0xF5 : 0xF4); // clientPin

        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.LARGE_BLOBS.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.LARGE_BLOBS, (short) 0,
                buffer, offset, (short) CannedCBOR.LARGE_BLOBS.length);
        buffer[offset++] = (byte) 0xF5; // largeBlobs = true

        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.PIN_UV_AUTH_TOKEN.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.PIN_UV_AUTH_TOKEN, (short) 0,
                buffer, offset, (short) CannedCBOR.PIN_UV_AUTH_TOKEN.length);
        buffer[offset++] = (byte) 0xF5; // pinUvAuthToken = true

        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.SET_MIN_PIN_LENGTH.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.SET_MIN_PIN_LENGTH, (short) 0,
                buffer, offset, (short) CannedCBOR.SET_MIN_PIN_LENGTH.length);
        buffer[offset++] = (byte) 0xF5; // setMinPINLength = true

        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.MAKE_CRED_UV_NOT_REQD.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.MAKE_CRED_UV_NOT_REQD, (short) 0,
                buffer, offset, (short) CannedCBOR.MAKE_CRED_UV_NOT_REQD.length);
        buffer[offset++] = (byte)(LOW_SECURITY_MAXIMUM_COMPLIANCE && !alwaysUv ? 0xF5 : 0xF4); // makeCredUvNotRequired = true or false

        if (includeMaxMsgSize) {
            buffer[offset++] = 0x05; // map key: maxMsgSize
            buffer[offset++] = 0x19; // two-byte integer
            offset = Util.setShort(buffer, offset, (short) bufferMem.length);
        }

        buffer[offset++] = 0x06; // map key: pinProtocols
        buffer[offset++] = (byte) 0x82; // array: two items
        buffer[offset++] = 0x02; // pin protocol version 2
        buffer[offset++] = 0x01; // pin protocol version 1

        buffer[offset++] = 0x07; // map key: maxCredentialCountInList
        buffer[offset++] = 0x17; // twenty-three

        final short amountInApduBuf = offset;

        final byte approximateKeyCount = getApproximateRemainingKeyCount();
        boolean partiallySent = false;
        if (!longResponse) {
            // We're going to have too much for one 256-byte buffer
            // So let's split into two halves, one directly APDU-written and one saved
            buffer = bufferMem;
            offset = 0;
        } else if (apdu.getBuffer().length > 300) {
            // We have an E-APDU, but there's room for our reply in the
            // APDU outgoing buffer: keep writing
        } else {
            // We have an E-APDU, buf there's not room for our response in the outgoing
            // buffer. Write aside.
            final short remainingAmountToWrite = (short)(CannedCBOR.ES256_ALG_TYPE.length
                    + (approximateKeyCount > 23 ? 2 : 1) // encoded length of approxKeyCount
                    + (minPinLength > 23 ? 2 : 1) // encoded length of minPinLength
                    + 23 // fixed overhead;
            );
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)(offset + remainingAmountToWrite));
            apdu.sendBytes((short) 0, offset);
            // And overwrite the same buffer again
            offset = 0;
            partiallySent = true;
        }

        buffer[offset++] = 0x08; // map key: maxCredentialIdLength: 1 byte
        offset = encodeIntTo(buffer, offset, (byte) CREDENTIAL_ID_LEN); // 2 bytes = 3

        buffer[offset++] = 0x0A; // map key: algorithms: 1 byte = 4
        offset = Util.arrayCopyNonAtomic(CannedCBOR.ES256_ALG_TYPE, (short) 0,
                buffer, offset, (short) CannedCBOR.ES256_ALG_TYPE.length); // added separately

        buffer[offset++] = 0x0B; // map key: maxSerializedLargeBlobArray: 1 byte = 5
        buffer[offset++] = 0x19; // two-byte integer: 1 byte = 6
        offset = Util.setShort(buffer, offset, (short) getCurrentLargeBlobStore().length); // 2 bytes = 8

        buffer[offset++] = 0x0C; // map key: forcePinChange: 1 byte = 9
        buffer[offset++] = (byte)(forcePinChange ? 0xF5 : 0xF4); // 1 byte = 10

        buffer[offset++] = 0x0D; // map key: minPinLength: 1 byte = 11
        offset = encodeIntTo(buffer, offset, minPinLength); // encoded separately

        buffer[offset++] = 0x0E; // map key: firmwareVersion: 1 byte = 12
        offset = encodeIntTo(buffer, offset, FIRMWARE_VERSION); // 1 byte = 13

        buffer[offset++] = 0x0F; // map key: maxCredBlobLength: 1 byte = 14
        offset = encodeIntTo(buffer, offset, MAX_CRED_BLOB_LEN); // 2 bytes = 16

        buffer[offset++] = 0x10; // map key: maxRPIDsForSetMinPinLength: 1 byte = 17
        offset = encodeIntTo(buffer, offset, MAX_RP_IDS_MIN_PIN_LENGTH); // 1 byte = 18

        buffer[offset++] = 0x12; // map key: uvModality: 1 byte = 19
        buffer[offset++] = 0x19; // two-byte integer: 1 byte = 20
        offset = Util.setShort(buffer, offset, (short) 0x0200); // uvModality "none": 2 bytes = 22

        if (includeCertifications) {
            buffer[offset++] = 0x13; // map key: certifications
            offset = Util.arrayCopyNonAtomic(CannedCBOR.FIDO_CERT_LEVEL, (short) 0,
                    buffer, offset, (short) CannedCBOR.FIDO_CERT_LEVEL.length);
            buffer[offset++] = CERTIFICATION_LEVEL;
        }

        buffer[offset++] = 0x14; // map key: remainingDiscoverableCredentials: 1 byte = 23
        offset = encodeIntTo(buffer, offset, approximateKeyCount); // variable

        if (longResponse) {
            if (partiallySent) {
                bufferManager.clear();
                apdu.sendBytes((short) 0, offset);
            } else {
                sendNoCopy(apdu, offset);
            }
        } else {
            sendNoCopy(apdu, amountInApduBuf);
            setupChainedResponse((short) 0, offset);
        }
    }

    /**
     * Returns the approximate number of discoverable credentials that may still be created
     *
     * @return Estimated number of creds
     */
    private static byte getApproximateRemainingKeyCount() {
        short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
        if (availableMem < 0) {
            availableMem = Short.MAX_VALUE;
        }
        final short approx = (short)(availableMem / APPROXIMATE_STORAGE_PER_RESIDENT_KEY);
        return (byte)(approx > 100 ? 100 : approx);
    }

    /**
     * Aborts processing and sends a particular status code to the platform.
     * Also releases any scratch memory and resets APDU chain handling state
     *
     * @param swCode Two-byte status code - may be SW_NO_ERROR if desired
     */
    private void throwException(short swCode) {
        throwException(swCode, true);
    }

    /**
     * As throwException, but optionally preserves iteration state
     *
     * @param swCode Two-byte status code - possibly SW_NO_ERROR
     * @param clearIteration If true, clears iteration state variables as per an exception. If false, leaves them,
     *                       allowing iteration calls like enumerateNextRP despite the "exception"
     */
    private void throwException(short swCode, boolean clearIteration) {
        if (clearIteration) {
            transientStorage.clearIterationPointers();
        }
        bufferManager.clear();
        ecKeyPair.getPrivate().clearKey();

        ISOException.throwIt(swCode);
    }

    /**
     * Dispatches a FIDO2 clientPin subcommand
     *
     * @param apdu    Request/response object
     * @param buffer  Buffer containing incoming request
     * @param lc      Length of incoming request, as sent by the platform
     */
    private void clientPINSubcommand(APDU apdu, byte[] buffer, short lc) {
        short readIdx = 1;

        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        final short numOptions = getMapEntryCount(apdu, buffer[readIdx++]);
        if (numOptions < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (readIdx >= (short)(lc - 4)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (buffer[readIdx++] != 0x01) { // map key: pinProtocol
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        final byte pinProtocol = buffer[readIdx++];
        checkPinProtocolSupported(apdu, pinProtocol);

        if (buffer[readIdx++] != 0x02) { // map key: subCommand
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        switch (buffer[readIdx++]) {
            case FIDOConstants.CLIENT_PIN_GET_KEY_AGREEMENT:
                handleClientPinGetAgreement(apdu);
                return;
            case FIDOConstants.CLIENT_PIN_GET_RETRIES:
                handleClientPinGetRetries(apdu);
                return;
            case FIDOConstants.CLIENT_PIN_SET_PIN:
                handleClientPinInitialSet(apdu, buffer, readIdx, lc, pinProtocol);
                return;
            case FIDOConstants.CLIENT_PIN_CHANGE_PIN:
                handleClientPinChange(apdu, buffer, readIdx, lc, pinProtocol);
                return;
            case FIDOConstants.CLIENT_PIN_GET_PIN_TOKEN:
                handleClientPinGetToken(apdu, buffer, readIdx, lc, pinProtocol, false, numOptions);
                return;
            case FIDOConstants.CLIENT_PIN_GET_PIN_TOKEN_USING_PIN_WITH_PERMISSIONS:
                handleClientPinGetToken(apdu, buffer, readIdx, lc, pinProtocol, true, numOptions);
                return;
            case FIDOConstants.CLIENT_PIN_GET_PIN_TOKEN_USING_UV_WITH_PERMISSIONS:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_SUBCOMMAND);
                break;
        }
    }

    /**
     * Processes the CTAP2 clientPin change subcommand
     *
     * @param apdu        Request/response object
     * @param buffer      Buffer containing incoming request
     * @param readIdx     Read index into request buffer
     * @param lc          Length of incoming request, as sent by the platform
     * @param pinProtocol Integer PIN protocol version in use
     */
    private void handleClientPinChange(APDU apdu, byte[] buffer, short readIdx, short lc, byte pinProtocol) {
        if (!pinSet) {
            // need to have a PIN to change a PIN...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        // 32 bytes for PIN hash (for PIN protocol 2) and 16 for IV on padded PIN
        short scratchHandle = bufferManager.allocate(apdu, (short)(PIN_PAD_LENGTH + 48), BufferManager.ANYWHERE);
        short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);

        readIdx = handlePinSetPreamble(apdu, buffer, readIdx, lc, scratch, scratchOff, true, pinProtocol);

        short wrappedPinLocation = readIdx;
        readIdx += PIN_PAD_LENGTH;
        if (pinProtocol == 2) {
            readIdx += 16; // IV for PIN pad
        }

        if (buffer[readIdx++] != 0x06) { // pinHashEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        // Decrypt the sent PIN hash using the shared secret
        readIdx = sharedSecretDecrypt(apdu, buffer, readIdx, lc, (byte) 16,
                scratch, scratchOff, pinProtocol, true);
        if (readIdx > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        // Use pinHash, now decrypted, to unlock the symmetric wrapping key (or fail if the PIN is wrong...)
        testAndReadyPIN(apdu, scratch, scratchOff, pinProtocol, (byte) 0x00);

        // Decrypt the real PIN
        sharedSecretDecrypt(apdu, buffer, wrappedPinLocation, lc, (byte) 64,
                scratch, scratchOff, pinProtocol, false);

        short realPinLength = 0;
        for (; realPinLength < PIN_PAD_LENGTH; realPinLength++) {
            if (scratch[(short)(scratchOff + realPinLength)] == 0x00) {
                break;
            }
        }
        if (realPinLength < 4 || realPinLength > 63) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        rawSetPIN(apdu, scratch, scratchOff, realPinLength);

        byte[] outBuf = apdu.getBuffer();
        outBuf[0] = FIDOConstants.CTAP2_OK; // no data in the response to this command, just an OK status
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Checks incoming pinHash and returns a pinToken to the platform for use in future commands
     * (until the next reset, of course...)
     *
     * @param apdu              Request/response object
     * @param inBuffer          Buffer containing incoming request (will be overwritten)
     * @param readIdx           Read index into request buffer
     * @param lc                Length of incoming request, as sent by the platform
     * @param pinProtocol       Integer PIN protocol version in use
     * @param expectPermissions If true, require permissions to be requested. If false, disallow them and use defaults
     * @param numOptions        Number of CBOR options present
     */
    private void handleClientPinGetToken(APDU apdu, byte[] inBuffer,
                                         short readIdx, short lc, byte pinProtocol, boolean expectPermissions,
                                         short numOptions) {
        if (!pinSet) {
            // duh
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_NOT_SET);
        }

        if (transientStorage.getPinTriesSinceReset() == PIN_TRIES_PER_RESET) {
            // Proceed no further: PIN is blocked until authenticator is powered off and on again
            // NO TOKEN FOR YOU. NEXT!
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_BLOCKED);
        }

        if (inBuffer[readIdx++] != 0x03) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readIdx = consumeKeyAgreement(apdu, inBuffer, readIdx, pinProtocol, lc);

        if (inBuffer[readIdx++] != 0x06) { // map key: pinHashEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        bufferManager.informAPDUBufferAvailability(apdu, readIdx);

        final short pinBufferHandle = bufferManager.allocate(apdu, (short) 16, BufferManager.ANYWHERE);
        final short pinBufferOffset = bufferManager.getOffsetForHandle(pinBufferHandle);
        final byte[] pinBuffer = bufferManager.getBufferForHandle(apdu, pinBufferHandle);

        // Decrypt the 16 bytes of PIN verification first
        readIdx = sharedSecretDecrypt(apdu, inBuffer, readIdx, lc, (byte) 16,
                pinBuffer, pinBufferOffset, pinProtocol, true);

        // parse permissions before readying the PIN, so that we can set the right perms on it
        byte permissions = (byte)(FIDOConstants.PERM_MAKE_CREDENTIAL | FIDOConstants.PERM_GET_ASSERTION);

        bufferManager.informAPDUBufferAvailability(apdu, readIdx);

        final short permRpIdHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.ANYWHERE);
        final short permRpIdOffset = bufferManager.getOffsetForHandle(permRpIdHandle);
        final byte[] permRpIdBuffer = bufferManager.getBufferForHandle(apdu, permRpIdHandle);
        short permRpIdLen = -1;

        if (expectPermissions) {
            if (readIdx == lc || numOptions < 5) {
                // We expect permissions, but we don't have any!
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (inBuffer[readIdx++] != 0x09) { // map key: permissions
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (inBuffer[readIdx] == 0x18) { // one-byte integer follows
                permissions = inBuffer[++readIdx];
                readIdx++;
            } else if (inBuffer[readIdx] < 0x18) { // in-place integer
                permissions = inBuffer[readIdx++];
            }

            if (numOptions == 6) {
                if (inBuffer[readIdx++] == 0x0A) { // map key: rpId
                    if (inBuffer[readIdx] >= 0x60 && inBuffer[readIdx] <= 0x77) {
                        // string with embedded length
                        permRpIdLen = (short)(inBuffer[readIdx++] - 0x60);
                    } else if (inBuffer[readIdx] == 0x78) {
                        // string with one-byte length
                        permRpIdLen = ub(inBuffer[++readIdx]);
                        readIdx++;
                    }
                    if (permRpIdLen <= 0) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }

                    sha256.doFinal(inBuffer, readIdx, permRpIdLen,
                            permRpIdBuffer, permRpIdOffset);

                    readIdx += permRpIdLen;
                    if (readIdx > lc) {
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                    }
                }
                // else ignore: could be options we don't support / know about
            }
        } else {
            if (numOptions > 4) {
                // We have more to read, but we don't expect anything more
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            }
        }

        if (permissions == 0) {
            // FIDO spec disallows providing empty permissions bitfield
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }

        if (expectPermissions && permRpIdLen == -1) {
            // We can't allow a makeCredential or getAssertion without an RP ID binding
            if ((permissions & FIDOConstants.PERM_MAKE_CREDENTIAL) != 0
                || (permissions & FIDOConstants.PERM_GET_ASSERTION) != 0) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
        }

        // Since we've now pulled everything we want out of the APDU buffer, it's all clear for temp space!
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

        testAndReadyPIN(apdu, pinBuffer, pinBufferOffset, pinProtocol, permissions);

        if (forcePinChange) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        if (permRpIdLen != -1) {
            permissionsRpId[0] = 0x01; // RP ID restriction enabled
            Util.arrayCopyNonAtomic(
                    permRpIdBuffer, permRpIdOffset,
                    permissionsRpId, (short) 1, RP_HASH_LEN
            );
        } else if (permissionsRpId[0] != 0x00) {
            // no permissions RP ID provided - disable
            permissionsRpId[0] = 0x00;
        }

        // Output below here

        short writeOffset = 0;
        final byte[] outBuffer = apdu.getBuffer();

        outBuffer[writeOffset++] = FIDOConstants.CTAP2_OK;
        outBuffer[writeOffset++] = (byte) 0xA1; // map: one item
        outBuffer[writeOffset++] = 0x02; // map key: pinToken
        writeOffset = sharedSecretEncrypt(pinToken, (short) 0, (short) pinToken.length, outBuffer, writeOffset,
                pinProtocol, true);

        sendNoCopy(apdu, writeOffset);
    }

    /**
     * Encrypt data destined for the platform using a shared secret, and pack the result into a target buffer
     *
     * @param inBuf Buffer containing data to be encrypted
     * @param inOffset Read offset into input buffer
     * @param length Length of data to be encrypted
     * @param outBuf Output buffer into which to write byte string with optional CBOR header
     * @param writeOffset Write offset into output buffer
     * @param pinProtocol Integer PIN protocol number
     * @param addCBORHeader If true, add CBOR byte array header to output as well
     *
     * @return New write index into output buffer after adding encrypted data
     */
    private short sharedSecretEncrypt(byte[] inBuf, short inOffset, short length, byte[] outBuf, short writeOffset,
                                      byte pinProtocol, boolean addCBORHeader) {
        short rawLength = length;
        if (pinProtocol == 2) {
            // byte array length includes 16-byte IV
            rawLength += 16;
        }

        if (addCBORHeader) {
            writeOffset = encodeIntLenTo(outBuf, writeOffset, rawLength, true);
        }

        if (pinProtocol == 2) {
            // Write out a random 16-byte IV and set up the wrapper to use it
            random.generateData(outBuf, writeOffset, (short) 16);
            sharedSecretWrapper.init(sharedSecretAESKey, Cipher.MODE_ENCRYPT, outBuf, writeOffset, (short) 16);
            writeOffset += 16;
        } else {
            sharedSecretWrapper.init(sharedSecretAESKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
        }

        writeOffset += sharedSecretWrapper.doFinal(inBuf, inOffset, length,
                outBuf, writeOffset);

        return writeOffset;
    }

    /**
     * Unwrap platform-encrypted data from a CBOR buffer into a designated output buffer
     *
     * @param apdu Request/response object
     * @param inBuf Buffer from which to read a CBOR byte array representing platform-encrypted data
     * @param readIdx Read index into input buffer
     * @param lc Length of incoming request, as sent by the platform
     * @param expectedLength How long the decrypted result should be
     * @param outputBuffer Buffer into which to write the decrypted result
     * @param outOff Offset into output buffer
     * @param pinProtocol Integer PIN protocol number
     * @param consumeCBOR If true, consume a CBOR byte array header before the data
     *
     * @return New read index into input buffer after consuming encrypted data
     */
    private short sharedSecretDecrypt(APDU apdu, byte[] inBuf, short readIdx, short lc, byte expectedLength,
                                      byte[] outputBuffer, short outOff, byte pinProtocol, boolean consumeCBOR) {
        byte rawLength = expectedLength;
        if (pinProtocol == 2) {
            // PIN protocol two means 16 bytes of IV before actual data, sooo...
            rawLength += 16;
        }

        if (consumeCBOR) {
            if (rawLength < 24) {
                // Single byte for type and length
                if (inBuf[readIdx++] != (byte)(0x40 + rawLength)) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            } else {
                if (inBuf[readIdx++] != 0x58) { // byte string, one-byte length
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (inBuf[readIdx++] != rawLength) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
            }
        }

        if (readIdx > (short)(lc - rawLength)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        if (pinProtocol == 2) {
            // Set IV and advance past it
            sharedSecretUnwrapper.init(sharedSecretAESKey, Cipher.MODE_DECRYPT, inBuf, readIdx, (short) 16);
            readIdx += 16;
        } else {
            sharedSecretUnwrapper.init(sharedSecretAESKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
        }

        short unwrapped = sharedSecretUnwrapper.doFinal(inBuf, readIdx, expectedLength,
                outputBuffer, outOff);
        if (unwrapped != expectedLength) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
        }

        return (short)(readIdx + expectedLength);
    }

    /**
     * Checks the SHA-256 hash of a PIN for correctness, and if it is correct, readies the authenticator unwrapping
     * key for use. After a successful call, wrappingKey is set and may be used for symmetric crypto
     *
     * @param apdu Request/response object
     * @param buf Buffer potentially containing the first 16 bytes of the SHA-256 hash of the PIN
     * @param off Offset of the putative PIN hash within the given buffer
     * @param pinProtocol PIN protocol used to pass PIN in
     * @param pinPermissions Bitfield representing permissions to be associated with the PIN if correct
     */
    private void testAndReadyPIN(APDU apdu, byte[] buf, short off, byte pinProtocol, byte pinPermissions) {
        short pinRetryIndex = pinRetryCounter.prepareIndex();
        if (pinRetryCounter.getRetryCount(pinRetryIndex) <= 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_BLOCKED);
        }

        if (transientStorage.getPinTriesSinceReset() >= PIN_TRIES_PER_RESET) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_BLOCKED);
        }

        final short bufLen = (short) 96;
        final short keyBufHandle = bufferManager.allocate(apdu, bufLen, BufferManager.ANYWHERE);
        final byte[] keyBuf = bufferManager.getBufferForHandle(apdu, keyBufHandle);
        final short keyOff = bufferManager.getOffsetForHandle(keyBufHandle);
        final short validationOff = (short)(keyOff + 32);

        // Use PBKDF on the hash to derive a potential PIN key
        PBKDF2(apdu, buf, off, keyBuf, keyOff);

        // Use high security wrapping key because it's always transient, and it's garbage right now anyhow
        highSecurityWrappingKey.setKey(keyBuf, keyOff);
        pinUnwrapper.init(highSecurityWrappingKey, Cipher.MODE_DECRYPT,
                highSecurityWrappingIV, (short) 0, (short) highSecurityWrappingIV.length);

        pinUnwrapper.doFinal(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length,
                keyBuf, keyOff);

        // Compute HMAC-SHA256 of first 32 bytes of wrappingKeyValidation
        hmacSha256(apdu, keyBuf, keyOff,
                   wrappingKeyValidation, (short) 0, (short) 32,
                   keyBuf, validationOff);

        // decrement retry counter *before* checking if it's correct:
        // this will be reset to max if it is correct, and otherwise it's theoretically possible to
        // remove power from the authenticator between it determining correctness and decrementing the
        // counter. So we'll accept the risk that a good PIN still results in the counter going down
        // in the event of a strange failure.
        transientStorage.incrementPinTriesSinceReset();
        pinRetryCounter.decrement(pinRetryIndex);

        // ... and check that the result equals the second 32 bytes. If it does, we have the correct key.
        if (Util.arrayCompare(wrappingKeyValidation, (short) 32,
                keyBuf, validationOff, (short) 32) == 0) {
            // Good PIN!
            pinRetryCounter.reset(pinRetryIndex);
            transientStorage.setPinProtocolInUse(pinProtocol, pinPermissions);
            highSecurityWrappingKey.setKey(keyBuf, keyOff);
            transientStorage.clearPinTriesSinceReset();
            bufferManager.release(apdu, keyBufHandle, bufLen);
            return;
        }

        // BAD PIN
        highSecurityWrappingKey.clearKey();
        forceInitKeyAgreementKey();
        if (pinRetryCounter.getRetryCount(pinRetryIndex) == 0) {
            // You've gone and done it now. You've failed so many times that the authenticator will permanently lock itself.
            resetWrappingKeys(apdu); // there won't be a situation where we can use this again, so clear it for safety
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_BLOCKED);
        }
        if (transientStorage.getPinTriesSinceReset() >= PIN_TRIES_PER_RESET) {
            // The authenticator isn't permanently blocked, but it will need to be powered off before trying again
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
    }

    /**
     * Performs heavy lifting for setting new PINs and changing existing ones. After a successful call,
     * the PIN is not necessarily correct, but the platform-authenticator shared secret is consistent with it.
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Starting index in request/response buffer of the keyAgreement (3rd) CTAP2 CBOR argument
     * @param lc Length of the incoming request, as declared by the platform
     * @param outBuf Buffer for result and scratch: minimum PIN_PAD_LENGTH+16 bytes allocated
     * @param outOffset Offset into output buffer. Again, must be at least PIN_PAD_LENGTH+16 bytes from the end of the buffer
     * @param expectPinHashEnc If true, expect that pinAuth matches hash(newPinEnc || pinHashEnc). In other words,
     *                         that an existing PIN was provided and this is a change-PIN operation
     * @param pinProtocol Integer PIN protocol version in use
     *
     * @return Index into request/response buffer of the encrypted new PIN
     */
    private short handlePinSetPreamble(APDU apdu, byte[] buffer, short readIdx, short lc, byte[] outBuf, short outOffset,
                                       boolean expectPinHashEnc, byte pinProtocol) {
        if (buffer[readIdx++] != 0x03) { // map key: keyAgreement
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        readIdx = consumeKeyAgreement(apdu, buffer, readIdx, pinProtocol, lc);

        if (buffer[readIdx++] != 0x04) { // map key: pinAuth
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short pinAuthLength = 16;
        if (pinProtocol == 1) {
            if (buffer[readIdx++] != 0x50) { // byte string: 16 bytes long
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else if (pinProtocol == 2) {
            if (buffer[readIdx++] != 0x58) { // byte string with one-byte length
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (buffer[readIdx++] != 0x20) { // 32 bytes long
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            pinAuthLength = 32;
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }
        short pinAuthIdx = readIdx;
        readIdx += pinAuthLength;

        if (buffer[readIdx++] != 0x05) { // map key: newPinEnc
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }

        short bLen = 0;
        byte pstrType = buffer[readIdx++];
        if (pstrType == 0x58) { // byte string, one-byte length
            bLen = ub(buffer[readIdx++]);
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short expectedLength = PIN_PAD_LENGTH;
        if (pinProtocol == 2) {
            expectedLength += 16; // 16-byte IV
        }

        if (bLen != expectedLength) { // standard-mandated minimum pad for PINs
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        // Verify pinAuth before we proceed
        if (expectPinHashEnc) {
            // Need to buffer-pack newPinEnc and pinHashEnc together before verifying
            short readAheadIdx = readIdx;

            Util.arrayCopyNonAtomic(buffer, readAheadIdx,
                    outBuf, outOffset, bLen);

            readAheadIdx += bLen;

            if (buffer[readAheadIdx++] != 0x06) { // pinHashEnc
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
            }
            if (pinProtocol == 1) {
                if (buffer[readAheadIdx++] != 0x50) { // byte array, 16 bytes long
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                Util.arrayCopyNonAtomic(buffer, readAheadIdx,
                        outBuf, (short)(outOffset + bLen), (short) 16);

                hmacSha256(apdu, sharedSecretVerifyKey, (short) 0,
                        outBuf, outOffset, (short)(bLen + 16),
                        outBuf, outOffset);
            } else {
                if (buffer[readAheadIdx++] != 0x58) { // byte string, one-byte length
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                if (buffer[readAheadIdx++] != 0x20) { // 32: sixteen bytes of IV and 16 bytes of hash
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                Util.arrayCopyNonAtomic(buffer, readAheadIdx,
                        outBuf, (short)(outOffset + bLen), (short) 32);

                hmacSha256(apdu, sharedSecretVerifyKey, (short) 0,
                        outBuf, outOffset, (short)(bLen + 32),
                        outBuf, outOffset);
            }
        } else {
            hmacSha256(apdu, sharedSecretVerifyKey, (short) 0,
                    buffer, readIdx, bLen,
                    outBuf, outOffset);
        }

        if (Util.arrayCompare(outBuf, outOffset,
                buffer, pinAuthIdx, pinAuthLength) != 0) {
            // Messed up crypto or invalid input: cannot proceed
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_INVALID);
        }

        // Verification OK
        if (readIdx > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        return readIdx;
    }

    /**
     * Handles the FIDO2 clientPin initial set subcommand
     *
     * @param apdu        Request/response object
     * @param buffer      Buffer containing incoming request
     * @param readIdx     Read index into request buffer
     * @param lc          Length of incoming request, as sent by the platform
     * @param pinProtocol Integer PIN protocol version in use
     */
    private void handleClientPinInitialSet(APDU apdu, byte[] buffer, short readIdx, short lc, byte pinProtocol) {
        if (pinSet) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        final short scratchHandle = bufferManager.allocate(apdu, (short) 80, BufferManager.ANYWHERE);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        final byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);

        readIdx = handlePinSetPreamble(apdu, buffer, readIdx, lc, scratch, scratchOff, false, pinProtocol);

        readIdx = sharedSecretDecrypt(apdu, buffer, readIdx, lc, (byte) 64,
                scratch, scratchOff, pinProtocol, false);
        if (readIdx > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short realPinLengthBytes = 0;
        short realPinLengthPoints = 0;
        short byteInCPCountDown = 0;
        for (; realPinLengthBytes < 64; realPinLengthBytes++) {
            byte curByte = scratch[(short)(scratchOff + realPinLengthBytes)];
            if (curByte == 0x00) {
                break;
            }
            if (byteInCPCountDown > 0) {
                if ((curByte & 0xC0) != 0x80) {
                    // invalid follow-up byte
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
                }
                byteInCPCountDown--;
            } else {
                realPinLengthPoints++;
                if ((curByte & 0x80) == 0x00) {
                    // one byte long
                } else if ((curByte & 0xE0) == 0xC0) {
                    // two bytes long
                    byteInCPCountDown = 1;
                } else if ((curByte & 0xF0) == 0xE0) {
                    // three bytes long
                    byteInCPCountDown = 2;
                } else if ((curByte & 0xF8) == 0xF0) {
                    // four bytes long - who uses one of these in their PIN?!
                    byteInCPCountDown = 3;
                }
            }
        }
        if (byteInCPCountDown > 0) {
            // invalid UTF-8
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if (realPinLengthPoints < minPinLength || realPinLengthPoints > 63) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        rawSetPIN(apdu, scratch, scratchOff, realPinLengthBytes);

        byte[] outBuf = apdu.getBuffer();
        outBuf[0] = FIDOConstants.CTAP2_OK;
        sendNoCopy(apdu, (short) 1);
    }

    /**
     * Consumes a CBOR object representing the platform's public key from an input buffer.
     *
     * After successful call, DH platform<->authenticator shared secret is available:
     * sharedSecretWrapper and sharedSecretUnwrapper may be used
     *
     * @param apdu Request/response object
     * @param buffer Buffer containing incoming request
     * @param readIdx Index of the platform public key in bufferMem
     * @param pinProtocol Integer PIN protocol version in use
     * @param lc Length of the incoming message, as sent by the platform
     *
     * @return New read index position in incoming buffer after consuming the key agreement CBOR block
     */
    private short consumeKeyAgreement(APDU apdu, byte[] buffer, short readIdx, byte pinProtocol,
                                      short lc) {
        if (buffer[readIdx++] != (byte) 0xA5) { // map, with five entries
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (Util.arrayCompare(buffer, readIdx,
                CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE, (short) 0, (short) CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE.length) != 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        readIdx += CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE.length;

        short xIdx = readIdx;
        readIdx += KEY_POINT_LENGTH;
        if (readIdx > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (buffer[readIdx++] != 0x22) { // map key: y-point
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (buffer[readIdx++] != 0x58) { // byte string, one-byte length
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        if (buffer[readIdx++] != KEY_POINT_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short yIdx = readIdx;
        readIdx += KEY_POINT_LENGTH;
        if (readIdx > lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        final short fullKeyLength = KEY_POINT_LENGTH * 2 + 1;

        // Pack the public key into a nice compact representation (mangling the buffer)
        short kpStart = (short)(yIdx - KEY_POINT_LENGTH - 1);
        Util.arrayCopyNonAtomic(buffer, xIdx,
                buffer, (short)(kpStart + 1), KEY_POINT_LENGTH); // place X just before Y and just after header
        buffer[kpStart] = 0x04; // "Uncompressed" EC point format - this idx is no longer in the x-point after we moved it

        final short secretOffset = (short)(readIdx - KEY_POINT_LENGTH);

        // DH-generate the shared secret... (overwriting the public key we just put in the buffer)
        short rawSecretLength = keyAgreement.generateSecret(
                buffer, kpStart, fullKeyLength,
                buffer, secretOffset
        );

        bufferManager.informAPDUBufferAvailability(apdu, secretOffset);

        if (pinProtocol == 1) {
            // This was a "plain" DH so we need to sha256 the result to get the real secret
            short sharedSecretLength = sha256.doFinal(buffer, secretOffset, rawSecretLength,
                    buffer, secretOffset);

            // Now, finally, the shared secret is ready!
            sharedSecretAESKey.setKey(buffer, secretOffset);
            Util.arrayCopyNonAtomic(buffer, secretOffset,
                    sharedSecretVerifyKey, (short) 0, sharedSecretLength);
        } else if (pinProtocol == 2) {
            // HKDF step one: get PRK by using zeros as a key to HMAC-SHA256 the IKM
            hmacSha256(apdu, FIDOConstants.ZERO_SALT, (short) 0,
                    buffer, secretOffset, rawSecretLength,
                    buffer, secretOffset
            );

            // HKDF step two (for HMAC key): use PRK as key to HMAC-SHA256 a different magic info string (plus a 0x01 byte)
            hmacSha256(apdu, buffer, secretOffset,
                    FIDOConstants.CTAP2_HMAC_KEY_INFO, (short) 0, (short) FIDOConstants.CTAP2_HMAC_KEY_INFO.length,
                    sharedSecretVerifyKey, (short) 0
            );

            // HKDF step two (for AES key): use PRK as key to HMAC-SHA256 a magic info string (plus a 0x01 byte)
            hmacSha256(apdu, buffer, secretOffset,
                    FIDOConstants.CTAP2_AES_KEY_INFO, (short) 0, (short) FIDOConstants.CTAP2_AES_KEY_INFO.length,
                    buffer, secretOffset
            );
            sharedSecretAESKey.setKey(buffer, secretOffset);
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }

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
        if (pinSet && transientStorage.getPinProtocolInUse() == 0) {
            // We already have a PIN, but we haven't unlocked with it this boot...
            // that's not going to work.
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_REQUIRED);
        }

        // Count the UTF-8 code points to determine if length sufficient, and store it if necessary
        short newPinCodePointLength = 0;
        for (short i = offset; i < (short)(pinLength + offset); i++) {
            newPinCodePointLength++;
            if ((pinBuf[i] & 0x80) == 0x00) {
                continue;
            } else if ((pinBuf[i] & 0xE0) == 0xC0) {
                i++;
            } else if ((pinBuf[i] & 0xF0) == 0xE0) {
                i += 2;
            } else if ((pinBuf[i] & 0xF8) == 0xF0) {
                i += 3;
            }
        }
        if (newPinCodePointLength < minPinLength) {
            // Too short, in UTF-8 terms, even though it's long enough in bytes...
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        // Take the SHA256 of the PIN before we start, and only pass the first 16 bytes to the change function
        // since that's all the protocol sends us to validate the PIN, that is our *real* PIN...
        sha256.doFinal(pinBuf, offset, pinLength,
                pinBuf, offset);

        final short bufLen = (short) 96;
        final short keyBufHandle = bufferManager.allocate(apdu, bufLen, BufferManager.ANYWHERE);
        final short keyOff = bufferManager.getOffsetForHandle(keyBufHandle);
        final byte[] keyBuf = bufferManager.getBufferForHandle(apdu, keyBufHandle);

        // Set pinWrapper to use a key we *derived* from the PIN
        // If the PIN is weak, this will modestly increase the difficulty of brute forcing the wrapping key
        PBKDF2(apdu, pinBuf, offset, keyBuf, keyOff);
        pinWrapKey.setKey(keyBuf, keyOff);

        bufferManager.release(apdu, keyBufHandle, bufLen);

        pinWrapper.init(pinWrapKey, Cipher.MODE_ENCRYPT,
                highSecurityWrappingIV, (short) 0, (short) highSecurityWrappingIV.length);

        // re-encrypt the current wrapping key using the PIN
        // and ATOMICALLY replace the old value with the new one at the same time as we change the PIN itself
        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            if (pinSet) {
                highSecurityWrappingKey.getKey(wrappingKeySpace, (short) 0);
            }

            pinSet = true;
            if (STORE_PIN_LENGTH) {
                pinCodePointLength = newPinCodePointLength;
            }
            short pinIdx = pinRetryCounter.prepareIndex();
            pinRetryCounter.reset(pinIdx);

            // Encrypt the wrapping key with the PIN key
            pinWrapper.doFinal(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length,
                    wrappingKeySpace, (short) 0);

            highSecurityWrappingKey.clearKey();
            pinWrapKey.clearKey();
            forcePinChange = false;

            resetPinUseState();

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
     * After call, output contains a 32-byte-long key deterministically derived from the incoming PIN.
     *
     * @param apdu Request/response object
     * @param pinBuf Buffer containing the (hashed) PIN, 16 bytes long
     * @param offset Offset of PIN in incoming buffer
     * @param output Buffer into which the new key should be written - must be 96 bytes long (not 32!)
     * @param outOff Offset into output buffer to write key
     */
    private void PBKDF2(APDU apdu, byte[] pinBuf, short offset, byte[] output, short outOff) {
        final short tempOff = (short)(outOff + 32);
        final short keyOff = (short)(outOff + 64);

        Util.arrayCopyNonAtomic(pinKDFSalt, (short) 0,
                output, outOff, (short) pinKDFSalt.length);
        // PBKDF2 has us concatenate the first iteration number (1) as a 32-bit int onto the end of the salt for iter1
        output[(short)(outOff + pinKDFSalt.length)] = 0x00;
        output[(short)(outOff + pinKDFSalt.length + 1)] = 0x00;
        output[(short)(outOff + pinKDFSalt.length + 2)] = 0x00;
        output[(short)(outOff + pinKDFSalt.length + 3)] = 0x01;
        for (short i = (short)(outOff + pinKDFSalt.length + 4); i < tempOff; i++) {
            output[i] = 0x00;
        }

        // Copy the 16 bytes of key and 16 zeroes into the scratch buffer to use as private key
        Util.arrayCopyNonAtomic(pinBuf, offset,
                output, keyOff, (short) 16);
        Util.arrayFillNonAtomic(output, (short)(keyOff + 16), (short) 16, (byte) 0x00);

        for (short i = 0; i < PIN_KDF_ITERATIONS; i++) {
            // Hash the current iteration value with the password-as-private-key HMAC
            hmacSha256(apdu, output, keyOff,
                    output, outOff, (short) 32,
                    output, tempOff);
            if (i == 0) {
                Util.arrayCopyNonAtomic(output, tempOff,
                        output, outOff, (short) 32);
            } else {
                // XOR the previous result with the new one
                for (short j = outOff; j < (short)(outOff + 32); j++) {
                    output[j] = (byte)(output[j] ^ output[(short)(j + 32)]);
                }
            }
        }
    }

    /**
     * Handle a clientPINGetAgreement CTAP2 request
     *
     * @param apdu The request/response object
     */
    private void handleClientPinGetAgreement(APDU apdu) {
        // Send public key of authenticatorKeyAgreementKey back

        byte[] outBuf = apdu.getBuffer();

        short outputLen = 0;
        outBuf[outputLen++] = FIDOConstants.CTAP2_OK;
        outBuf[outputLen++] = (byte) 0xA1; // map - one entry
        outBuf[outputLen++] = 0x01; // map key: keyAgreement
        outBuf[outputLen++] = (byte) 0xA5; // map: five entries
        outputLen = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE, (short) 0,
                outBuf, outputLen, (short) CannedCBOR.PUBLIC_KEY_DH_ALG_PREAMBLE.length);


        // Place public key into UPPER half of APDU buffer, away from where we are building the response

        ((ECPublicKey) authenticatorKeyAgreementKey.getPublic()).getW(outBuf, (short) 128);
        outputLen = writePubKey(outBuf, outputLen, outBuf, (short) 129); // note: +1 to skip keyEncodingType byte

        sendNoCopy(apdu, outputLen);
    }

    /**
     * Handle a clientPINGetRetries CTAP2 request
     *
     * @param apdu The request/response object
     */
    private void handleClientPinGetRetries(APDU apdu) {
        short pinIdx = pinRetryCounter.prepareIndex();

        byte[] outBuf = apdu.getBuffer();
        short outputLen = 0;
        outBuf[outputLen++] = FIDOConstants.CTAP2_OK;
        outBuf[outputLen++] = (byte) 0xA2; // map - two entries
        outBuf[outputLen++] = 0x03; // map key: retries
        outBuf[outputLen++] = pinRetryCounter.getRetryCount(pinIdx);
        outBuf[outputLen++] = 0x04; // map key: powerCycleState
        outBuf[outputLen++] = (byte) (transientStorage.getPinTriesSinceReset() >= PIN_TRIES_PER_RESET
                ? 0xF5 : 0xF4); // true or false

        sendNoCopy(apdu, outputLen);
    }

    /**
     * Forcibly refresh per-boot data. This includes the PIN token and the ephemeral EC pair used for
     * DH between the platform and the authenticator.
     * TRASHES BUFFERMEM
     */
    private void forceInitKeyAgreementKey() {
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPrivate());
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPublic());
        if (!makeGoodKeyPair(authenticatorKeyAgreementKey, bufferMem, (short) (bufferMem.length - 128))) {
            throwException(ISO7816.SW_DATA_INVALID);
        }
        keyAgreement.init(authenticatorKeyAgreementKey.getPrivate());

        resetPinUseState();

        transientStorage.setPlatformKeySet();
    }

    /**
     * Reset the current PIN protocol/token in use.
     */
    private void resetPinUseState() {
        transientStorage.setPinProtocolInUse((byte) 0, (byte) 0);
        random.generateData(pinToken, (short) 0, (short) pinToken.length);
    }

    /**
     * If the authenticator-to-and-from-platform key agreement hasn't already been set up this boot, set it up
     */
    private void initKeyAgreementKeyIfNecessary() {
        if (!transientStorage.isPlatformKeySet()) {
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
        transientStorage.clearOnDeselect();

        // Other stuff
        permissionsRpId[0] = 0x00;
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
     * @param forceAllowTransient If true, allow this PRIVATE key to be in transient memory
     * @param allowDeselectMemory If true, allow this key to be cleared on applet deselect - unusual for private keys...
     * @return An uninitialized EC private key, ideally in RAM, but in flash if the authenticator doesn't support in-memory
     */
    private ECPrivateKey getECPrivKey(boolean forceAllowTransient, boolean allowDeselectMemory) {
        if (forceAllowTransient) {
            if (allowDeselectMemory) {
                try {
                    return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
                } catch (CryptoException e) {
                    // Oh well, unsupported, use normal RAM or flash instead
                }
            }

            try {
                return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
            } catch (CryptoException e) {
                // Oh well, unsupported, use flash instead
            }
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
     * Entry point for installing the applet!
     * @param array install parameters array
     * @param offset install parameters offset
     * @param length install parameters length
     * @throws ISOException If anything goes wrong during installation
     */
    @SuppressWarnings("unused")
    public static void install(byte[] array, short offset, byte length)
            throws ISOException {
        if (length > 0) {
            short aidLen = ub(array[offset]);
            short infoLen = ub(array[(short)(offset + aidLen + 1)]);
            length = array[(short)(offset + aidLen + infoLen + 2)];
            offset = (short)(offset + aidLen + infoLen + 3);
        }
        FIDO2Applet applet = new FIDO2Applet(array, offset, length);

        // Javacard API requires this call to know we succeeded and set the app up with the platform
        applet.register();
    }

    /**
     * Setup method preparing all the internal state
     *
     * @param array install parameters array
     * @param offset install parameters offset
     * @param length install parameters length
     */
    @SuppressWarnings("unused")
    private FIDO2Applet(byte[] array, short offset, byte length) {
        // set up parameters
        // first, defaults
        attestationSwitchingEnabled = false;
        LOW_SECURITY_MAXIMUM_COMPLIANCE = true;
        FORCE_ALWAYS_UV = false;
        USE_LOW_SECURITY_FOR_SOME_RKS = true;
        PROTECT_AGAINST_MALICIOUS_RESETS = false;
        ONE_USE_PER_PIN_TOKEN = false;
        WRITES_INVALIDATE_PINS = true;
        PIN_KDF_ITERATIONS = 5;
        MAX_CRED_BLOB_LEN = 32;
        short largeBlobStoreSize = 1024;
        MAX_RESIDENT_RP_ID_LENGTH = 32;
        MAX_RAM_SCRATCH_SIZE = 512;
        BUFFER_MEM_SIZE = 1024;
        FLASH_SCRATCH_SIZE = 1024;
        STORE_PIN_LENGTH = true;
        CERTIFICATION_LEVEL = 0;

        // Next, read any overrides
        final short initOffset = offset;
        if (length > 0) {
            short sb = ub(array[offset++]);
            short numOptions = (short)(sb - 0xA0);
            for (; numOptions > 0; numOptions--) {
                if (offset > (short)(length + initOffset - 1)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                switch (array[offset++]) {
                    case 0x00:
                        attestationSwitchingEnabled = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x01:
                        LOW_SECURITY_MAXIMUM_COMPLIANCE = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x02:
                        FORCE_ALWAYS_UV = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x03:
                        USE_LOW_SECURITY_FOR_SOME_RKS = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x04:
                        PROTECT_AGAINST_MALICIOUS_RESETS = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x05:
                        PIN_KDF_ITERATIONS = array[offset++];
                        break;
                    case 0x06:
                        if (array[offset++] != 0x18) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        MAX_CRED_BLOB_LEN = array[offset++];
                        if (MAX_CRED_BLOB_LEN < 32) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x07:
                        if (array[offset++] != 0x19) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        largeBlobStoreSize = Util.getShort(array, offset);
                        if (largeBlobStoreSize < 1024) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        offset += 2;
                        break;
                    case 0x08:
                        if (array[offset++] != 0x18) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        MAX_RESIDENT_RP_ID_LENGTH = array[offset++];
                        if (MAX_RESIDENT_RP_ID_LENGTH < 32) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x09:
                        if (array[offset] == 0x18) {
                            offset++;
                            MAX_RAM_SCRATCH_SIZE = ub(array[offset]);
                            offset++;
                        } else if (array[offset] == 0x19) {
                            offset++;
                            MAX_RAM_SCRATCH_SIZE = Util.getShort(array, offset);
                            offset += 2;
                        } else {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x0A:
                        if (array[offset++] != 0x19) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        BUFFER_MEM_SIZE = Util.getShort(array, offset);
                        offset += 2;
                        break;
                    case 0x0B:
                        if (array[offset] == 0x18) {
                            offset++;
                            FLASH_SCRATCH_SIZE = ub(array[offset]);
                            offset++;
                        } else if (array[offset] == 0x19) {
                            offset++;
                            FLASH_SCRATCH_SIZE = Util.getShort(array, offset);
                            offset += 2;
                        } else if (ub(array[offset]) <= 0x17) {
                            FLASH_SCRATCH_SIZE = ub(array[offset++]);
                        } else {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x0C:
                        STORE_PIN_LENGTH = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x0D:
                        ONE_USE_PER_PIN_TOKEN = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x0E:
                        CERTIFICATION_LEVEL = array[offset++];
                        break;
                    case 0x0F:
                        if (array[offset++] != 0x58 || array[offset++] != 0x20) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        offset += loadAttestationPrivateKey(array, offset);
                        break;
                    case 0x10:
                        WRITES_INVALIDATE_PINS = array[offset++] == (byte) 0xF5;
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }

        alwaysUv = FORCE_ALWAYS_UV;

        // Flash usage
        pinKDFSalt = new byte[28];
        wrappingKeySpace = new byte[32];
        wrappingKeyValidation = new byte[64];
        hmacWrapperBytesUV = new byte[32];
        hmacWrapperBytesNoUV = new byte[32];
        credentialVerificationKey = new byte[32];
        highSecurityWrappingIV = new byte[IV_LEN];
        largeBlobStoreA = new byte[largeBlobStoreSize];
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0,
                largeBlobStoreA, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);
        largeBlobStoreB = new byte[largeBlobStoreSize];
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0,
                largeBlobStoreB, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);
        largeBlobStoreFill = (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length;
        highSecurityWrappingKey = getTransientAESKey(); // Our most important treasure, from which all other crypto is born...
        lowSecurityWrappingKey = getPersistentAESKey(); // Not really a treasure
        residentKeys = new ResidentKeyData[NUM_RESIDENT_KEY_SLOTS_PER_BATCH];
        minPinRPIDs = new byte[MAX_RP_IDS_MIN_PIN_LENGTH * RP_HASH_LEN];
        numResidentCredentials = 0;
        numResidentRPs = 0;
        resetRequested = false;
        counter = new SigOpCounter();
        pinRetryCounter = new PinRetryCounter(MAX_PIN_RETRIES);
        pinCodePointLength = 0;

        // Trivial amounts of flash, object allocations without buffers
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        pinUnwrapper = getAES();
        pinWrapper = getAES();
        symmetricWrapper = getAES();
        symmetricUnwrapper = getAES();
        sharedSecretWrapper = getAES();
        sharedSecretUnwrapper = getAES();
        attester = getECSig();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        transientStorage = new TransientStorage();

        final short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);

        boolean authenticatorKeyInRam = availableMem >= 148; // 96 (desired scratch)+6 (overhead)+32 (key)+16 (params)
        boolean ecPairInRam = availableMem >= 180; // 148 + 32 (key)

        initAuthenticatorKey(authenticatorKeyInRam);
        initCredKey(ecPairInRam);
    }

    /**
     * Initializes the platform-to-authenticator key agreement object.
     *
     * @param authenticatorKeyInRam If true, try to place the private key in transient memory
     */
    private void initAuthenticatorKey(boolean authenticatorKeyInRam) {
        authenticatorKeyAgreementKey = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey(authenticatorKeyInRam, false)
        );
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPrivate());
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPublic());
    }

    /**
     * Initialize the per-credential key object.
     *
     * @param ecPairInRam If true, try to place the private key in transient memory
     */
    private void initCredKey(boolean ecPairInRam) {
        // RAM usage - (ideally) ephemeral keys
        ecKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey(ecPairInRam, true)
        );
        P256Constants.setCurve((ECKey) ecKeyPair.getPrivate());
        P256Constants.setCurve((ECKey) ecKeyPair.getPublic());
    }

    /**
     * Initialize non-self attestation mode.
     *
     * This installs an AAGUID and a certificate chain for signing credentials,
     * instead of them being signed with their own private keys.
     *
     * @param apdu Optional (nullable) APDU context object
     * @param params Byte array of encoded parameters:
     *               - aaguid
     *               - private key point
     *               - certificate chain. CBOR-encoded
     * @param offset Offset into params array of start of data
     * @param length Length of parameter data loaded in buffer
     * @return true if we're done reading the keys
     */
    private boolean initAttestationKeyStart(APDU apdu, byte[] params, short offset, short length) {
        if (!counter.isZero()) {
            // Too late!
            if (apdu != null) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
            }
            throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (!attestationSwitchingEnabled) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
        }

        short minLength = (short)(aaguid.length + 4);
        if (attestationKey == null) {
            minLength += KEY_POINT_LENGTH;
        }

        if (length <= minLength) {
            if (apdu != null) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
            }
            throwException(ISO7816.SW_DATA_INVALID);
        }

        JCSystem.beginTransaction();
        boolean success = false;
        try {
            attestationSwitchingEnabled = false; // We're loading a cert here and now.

            Util.arrayCopy(params, offset, aaguid, (short) 0, (short) aaguid.length);
            offset += (short) aaguid.length;
            short amountToRead = (short)(length - aaguid.length - 2);

            if (attestationKey == null) {
                offset += loadAttestationPrivateKey(params, offset);
                amountToRead -= KEY_POINT_LENGTH;
            }

            final short expectedLength = Util.getShort(params, offset);
            offset += 2;

            if (amountToRead > expectedLength) {
                if (apdu != null) {
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
                }
                throwException(ISO7816.SW_DATA_INVALID);
            }

            if ((params[offset] & 0xF0) != 0x80) {
                // These bytes should/must be a CBOR array
                // it's doubtful trying to use >15 certificates is a good idea, either
                throwException(ISO7816.SW_DATA_INVALID);
            }

            attestationData = new byte[expectedLength];
            filledAttestationData = amountToRead;
            Util.arrayCopy(params, offset,
                    attestationData, (short) 0, amountToRead);

            if (filledAttestationData == attestationData.length) {
                // Done!
                if (apdu != null) {
                    final byte[] buffer = apdu.getBuffer();
                    buffer[0] = FIDOConstants.CTAP2_OK;
                    sendNoCopy(apdu, (short) 1);
                }
                success = true;
                return true;
            }

            success = true;
        } finally {
            if (success) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        return false;
    }

    private short loadAttestationPrivateKey(byte[] params, short offset) {
        attestationKey = getECPrivKey(false, false);
        P256Constants.setCurve(attestationKey);
        attestationKey.setS(params, offset, KEY_POINT_LENGTH);
        return KEY_POINT_LENGTH;
    }

    /**
     * Continue loading part of an attestation key; used as part of initial setup for basic auth.
     *
     * @param apdu Request/response context object
     * @param buffer Incoming request buffer
     * @param offset Read offset in incoming buffer
     * @param lc Declared incoming request length
     * @return true if attestation key now completely loaded; false otherwise
     */
    private boolean initAttestationKeyContinue(APDU apdu, byte[] buffer, short offset, short lc) {
        if (attestationData == null || filledAttestationData == attestationData.length) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
        }
        final short amountRemaining = (short) (attestationData.length - filledAttestationData);
        if (lc > amountRemaining) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
        }
        JCSystem.beginTransaction();
        boolean ok = false;
        boolean done;
        try {
            Util.arrayCopy(buffer, offset,
                    attestationData, filledAttestationData, lc);
            filledAttestationData += lc;
            done = filledAttestationData == attestationData.length;
            if (done) {
                // Loaded up, ready to go, locked
                attestationSwitchingEnabled = false;
            }
            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        if (done) {
            final byte[] apduBuf = apdu.getBuffer();
            apduBuf[0] = FIDOConstants.CTAP2_OK;
            sendNoCopy(apdu, (short) 1);
        }
        return done;
    }

    /**
     * Allocates a new byte buffer.
     *
     * @param len Number of bytes to allocate
     * @param inRAM If true, prefer RAM (still fall back to flash)
     * @return Newly created byte array
     */
    private byte[] getTempOrFlashByteBuffer(short len, boolean inRAM) {
        if (inRAM) {
            return JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        }

        // Yuck.
        return new byte[len];
    }

    /**
     * Second-phase initialize state-keeping objects for the application.
     *
     * This cannot be called on initial install because the smartcard will generally have some memory reserved
     * for app-install-specific data structures, leading to wasted memory!
     *
     * @param apdu Request/response object, used for determining APDU buffer sizes
     */
    private void initTransientStorage(APDU apdu) {
        final boolean apduBufferIsLarge = apdu.getBuffer().length >= 2048;

        short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);

        if ((apduBufferIsLarge && availableMem > 64) || availableMem > 300) {
            // Attempt to re-initialize EC key pairs into RAM, since the large APDU buffer means they're more
            // important than our in-memory general scratch buffer!
            if (authenticatorKeyAgreementKey.getPrivate().getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
                initAuthenticatorKey(true);
                P256Constants.setCurve((ECPrivateKey) authenticatorKeyAgreementKey.getPrivate());
                P256Constants.setCurve((ECPublicKey) authenticatorKeyAgreementKey.getPublic());
            }

            if (ecKeyPair.getPrivate().getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
                initCredKey(true);
                P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
                P256Constants.setCurve((ECPublicKey) ecKeyPair.getPublic());
            }

            availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);

            try {
                JCSystem.requestObjectDeletion();
            } catch (Exception e) {
                // Whoops. Wasted some flash, I guess.
            }
        }

        short targetMemAmount = 99; // 96+3=99 bytes desired RAM buffer left over, enough room for one 32-byte HMAC
        if (apduBufferIsLarge) {
            targetMemAmount = 3; // Down to the bone
        }

        // Prioritize putting more frequently written things into RAM
        final boolean pinTokenInRam = availableMem >= (short)(targetMemAmount + 32);
        if (pinTokenInRam) {
            targetMemAmount += 32;
        }
        pinToken = getTempOrFlashByteBuffer((short) 32, pinTokenInRam);
        final boolean sharedSecretVerifyInRam = availableMem >= (short)(targetMemAmount + 32);
        if (sharedSecretVerifyInRam) {
            targetMemAmount += 32;
        }
        sharedSecretVerifyKey = getTempOrFlashByteBuffer((short) 32, sharedSecretVerifyInRam);
        final boolean permRpIdInRam = availableMem >= (short)(targetMemAmount + RP_HASH_LEN + 1);
        if (permRpIdInRam) {
            targetMemAmount += RP_HASH_LEN;
            targetMemAmount++;
        }
        permissionsRpId = getTempOrFlashByteBuffer((short)(RP_HASH_LEN + 1), permRpIdInRam);

        if (availableMem >= (short)(targetMemAmount + 32)) {
            targetMemAmount += 32;
            sharedSecretAESKey = getTransientAESKey();
        } else {
            sharedSecretAESKey = getPersistentAESKey();
        }
        if (availableMem >= (short)(targetMemAmount + 32)) {
            targetMemAmount += 32;
            pinWrapKey = getTransientAESKey();
        } else {
            pinWrapKey = getPersistentAESKey();
        }

        boolean requestBufferInRam = availableMem >= (short)(targetMemAmount + BUFFER_MEM_SIZE);
        if (requestBufferInRam) {
            targetMemAmount += BUFFER_MEM_SIZE;
        }
        bufferMem = getTempOrFlashByteBuffer(BUFFER_MEM_SIZE, requestBufferInRam);

        initKeyAgreementKeyIfNecessary();

        // Five things are truly random and persist until we hard-FIDO2-reset the authenticator:
        // - The wrapping key (generated at first use of the applet)
        // - the salt we use for deriving keys from PINs
        random.generateData(pinKDFSalt, (short) 0, (short) pinKDFSalt.length);
        // - the IV we use for encrypting and decrypting blobs sent by the authenticator TO the authenticator
        random.generateData(highSecurityWrappingIV, (short) 0, (short) highSecurityWrappingIV.length);
        // - the keys we use for converting a credential private key into an hmac-secret ... uh ... secret
        random.generateData(hmacWrapperBytesUV, (short) 0, (short) hmacWrapperBytesUV.length);
        random.generateData(hmacWrapperBytesNoUV, (short) 0, (short) hmacWrapperBytesNoUV.length);
        // - the key for verifying credential blobs
        random.generateData(credentialVerificationKey, (short) 0, (short) credentialVerificationKey.length);

        if (Util.arrayCompare(hmacWrapperBytesUV, (short) 0,
                hmacWrapperBytesNoUV, (short) 0, (short) hmacWrapperBytesUV.length) == 0) {
            // We can't work without a real random number generator
            throwException(ISO7816.SW_DATA_INVALID);
        }
    }

}
