package us.q3q.fido2;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * This class stores all the data associated with a Discoverable Credential
 * (also called a Resident Key). It doesn't handle encrypting the credential
 * ID itself, but does make sure all the other data around the credential are
 * appropriately protected.
 */
public class ResidentKeyData {
    /**
     * How long, in bytes, initialization vectors within this class are
     */
    private static final short IV_LEN = 16;

    /**
     * Initialization vectors used for encryption in this class
     */
    private final byte[] IVs;
    /**
     * Offset in IVs of IV for encrypting the user info
     */
    private static final short USER_ID_IV_OFFSET = 0;
    /**
     * Offset in IVs of IV for encrypting the user name
     */
    private static final short USER_NAME_IV_OFFSET = USER_ID_IV_OFFSET + IV_LEN;
    /**
     * Offset in IVv of IV for encrypting the RP info (text, not a hash)
     */
    private static final short RP_IV_OFFSET = USER_NAME_IV_OFFSET + IV_LEN;
    /**
     * Offset in IVs of IV for encrypting the credential's large blob data
     */
    private static final short LARGE_BLOB_IV_OFFSET = USER_NAME_IV_OFFSET + IV_LEN;
    /**
     * Offset in IVs of IV for encrypting the credential's credBlob (opaque platform-driven storage)
     */
    private static final short CRED_BLOB_IV_OFFSET = LARGE_BLOB_IV_OFFSET + IV_LEN;

    /**
     * Encrypted-as-usual credential ID field, just like we'd receive in incoming blocks
     * from the platform if they were non-resident
     */
    private byte[] credential;
    /**
     * Whether this credential is likely for a "unique" RP
     */
    private boolean uniqueRP;
    /**
     * The level of protection required for this credential - 1, 2, or 3
     *
     * Multiplied by negative one if the key was "high security" encrypted
     */
    private byte credProtectLevel;
    /**
     * Encrypted (with the device wrapping key) user ID field
     */
    private byte[] userId;
    /**
     * Length of the corresponding user ID
     */
    private byte userIdLength;
    /**
     * Encrypted (with the device wrapping key) user name field
     */
    private byte[] userName;
    /**
     * Length of the corresponding user name
     */
    private byte userNameLength;
    /**
     * Encrypted (with the device wrapping key) RP ID fields for resident keys
     */
    private byte[] rpId;
    /**
     * Length of the corresponding RP IDs
     */
    private byte rpIdLength;
    /**
     * Encrypted (with the device wrapping key) public key X+Y point data for resident keys
     */
    private final byte[] publicKey;
    /**
     * Encrypted (with the device wrapping key) credBlobs for resident keys
     */
    private final byte[] credBlob;
    /**
     * The valid length of the credBlob
     */
    private final byte credBlobLen;

    /**
     * Create a ResidentKeyData instance.
     *
     * @param random Source of randomness for initialization vectors
     * @param key Key to use for encrypting data inside the RK
     * @param wrapper Cipher for RK encryption
     * @param publicKeyBuffer Buffer containing the public key for this RK's keypair
     * @param publicKeyOffset Offset of the public key within given buffer
     * @param publicKeyLength Length of the public key in bytes
     * @param credBlobBuffer Buffer containing a credBlob - unused if credBlobLen is zero
     * @param credBlobOffset Offset of credBlob within buffer - unused if credBlobLen is zero
     * @param credBlobLen Length of given credBlob to store with the RK
     * @param uniqueRP True if this RK is the (probably) the only one for its RP
     */
    public ResidentKeyData(RandomData random, AESKey key, Cipher wrapper,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength,
                           byte[] credBlobBuffer, short credBlobOffset, byte credBlobLen,
                           boolean uniqueRP) {
        short ivBufferLen = CRED_BLOB_IV_OFFSET;
        if (credBlobLen > 0) {
            ivBufferLen += IV_LEN;
        }
        IVs = new byte[ivBufferLen];
        random.generateData(IVs, (short) 0, ivBufferLen);

        if (credBlobLen > 0) {
            credBlob = new byte[encryptableLength(credBlobLen)];
            wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, CRED_BLOB_IV_OFFSET, IV_LEN);
            wrapper.doFinal(credBlobBuffer, credBlobOffset, (short) credBlob.length,
                    credBlob, (short) 0);
            this.credBlobLen = credBlobLen;
        } else {
            credBlob = null;
            this.credBlobLen = 0;
        }

        publicKey = new byte[publicKeyLength];
        Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                publicKey, (short) 0, publicKeyLength);

        this.uniqueRP = uniqueRP;
    }

    /**
     * Sets the actual Credential ID stored by this RK.
     *
     * @param credBuffer Buffer containing ready-to-use Credential ID
     * @param credOffset Offset of credential within given buffer
     * @param credLen Length of credential
     * @param credProtectLevel Level of credential protection applied to this RK
     * @param highSecEncrypted If true, encrypted with the "high security" key
     */
    public void setEncryptedCredential(byte[] credBuffer, short credOffset, short credLen, byte credProtectLevel, boolean highSecEncrypted) {
        if (credential != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        this.credential = new byte[credLen];
        Util.arrayCopy(credBuffer, credOffset,
                this.credential, (short) 0, credLen);

        if (highSecEncrypted) {
            this.credProtectLevel = (byte) (-1 * credProtectLevel);
        } else {
            this.credProtectLevel = credProtectLevel;
        }
    }

    /**
     * We can only encrypt/decrypt in 16-byte chunks.
     *
     * This determines how much must be stored to hold a value of the given length.
     *
     * @param rawLength Original length value
     * @return Multiple of encryptable byte length that will contain rawLength
     */
    private short encryptableLength(short rawLength) {
        short num16s = (short)(rawLength >> 4);
        if ((rawLength & 0x0F) != 0) {
            num16s += 1;
        }
        return (short)(num16s * 16);
    }

    /**
     * Set the Relying Party ID (note: not hash) for this key.
     *
     * @param key Key to use in encrypting the Relying Party ID
     * @param wrapper Encryption object for the RP ID
     * @param rpIdBuffer Buffer containing the unencrypted Relying Party ID
     * @param rpIdOffset Offset of RPID within given buffer
     * @param rpIdLength Length of RPID being stored
     */
    public void setRpId(AESKey key, Cipher wrapper, byte[] rpIdBuffer, short rpIdOffset, byte rpIdLength) {
        if (rpId != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        rpId = new byte[encryptableLength(rpIdLength)];
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, RP_IV_OFFSET, IV_LEN);
        wrapper.doFinal(rpIdBuffer, rpIdOffset, (short) rpId.length,
                rpId, (short) 0);
        this.rpIdLength = rpIdLength;
    }

    /**
     * Set user information - ID and name - for this RK.
     *
     * @param key Encryption key to use for storing data
     * @param wrapper Encryption object to wrap data
     * @param userIdBuffer Buffer containing user ID (not name)
     * @param userIdOffset Offset of user ID within given buffer
     * @param userIdLength Length of user ID
     * @param userNameBuffer Buffer containing user name (plain text)
     * @param userNameOffset Offset of user name within given buffer
     * @param userNameLength Length of user name to store
     */
    public void setUser(AESKey key, Cipher wrapper,
                        byte[] userIdBuffer, short userIdOffset, byte userIdLength,
                        byte[] userNameBuffer, short userNameOffset, byte userNameLength) {
        final short newUserIdBufferLength = encryptableLength(userIdLength);
        if (userId == null || newUserIdBufferLength > userId.length) {
            userId = new byte[encryptableLength(userIdLength)];
        }
        Util.arrayCopy(userIdBuffer, userIdOffset,
                userId, (short) 0, userIdLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, USER_ID_IV_OFFSET, IV_LEN);
        wrapper.doFinal(userId, (short) 0, (short) userId.length,
                userId, (short) 0);
        this.userIdLength = userIdLength;

        if (userNameLength > 64) {
            // let's truncate the user name
            userNameLength = 64;
        }

        short newUserNameBufferLength = encryptableLength(userNameLength);
        if (userName == null || newUserNameBufferLength > userName.length) {
            userName = new byte[newUserNameBufferLength];
        }
        Util.arrayCopy(userNameBuffer, userNameOffset,
                userName, (short) 0, userNameLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, USER_NAME_IV_OFFSET, IV_LEN);
        wrapper.doFinal(userName, (short) 0, (short) userName.length,
                userName, (short) 0);
        this.userNameLength = userNameLength;
    }

    /**
     * Decrypt and extract the user unique ID for this RK.
     *
     * @param key Key for decryption - must match one given to setUser
     * @param unwrapper Decryption object to use
     * @param targetBuffer Buffer into which to store the unpacked user ID
     * @param targetOffset Offset at which to store the user ID
     */
    public void unpackUserID(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, USER_ID_IV_OFFSET, IV_LEN);
        unwrapper.doFinal(userId, (short) 0, (short) userId.length,
                targetBuffer, targetOffset);
    }

    /**
     * Decrypt and extract the user name (not ID, not displayName) for this RK.
     *
     * @param key Key for decryption - must match one given to setUser
     * @param unwrapper Decryption object to use
     * @param targetBuffer Buffer into which to store the unpacked username
     * @param targetOffset Offset at which to store the username
     */
    public void unpackUserName(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, USER_NAME_IV_OFFSET, IV_LEN);
        unwrapper.doFinal(userName, (short) 0, (short) userName.length,
                targetBuffer, targetOffset);
    }

    /**
     * Extract the public key for this RK.
     *
     * @param targetBuffer Buffer into which to store the pubKey
     * @param targetOffset Offset at which to store the pubKey
     */
    public void unpackPublicKey(byte[] targetBuffer, short targetOffset) {
        Util.arrayCopyNonAtomic(publicKey, (short) 0,
                targetBuffer, targetOffset, (short) publicKey.length);
    }

    /**
     * Decrypt and extract the relying party ID associated with this RK.
     *
     * @param key Key for decryption
     * @param unwrapper Decryption object to use
     * @param targetBuffer Buffer into which to store the RPID
     * @param targetOffset Offset at which to store the RPID
     */
    public void unpackRpId(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, RP_IV_OFFSET, IV_LEN);
        unwrapper.doFinal(rpId, (short) 0, (short) rpId.length,
                targetBuffer, targetOffset);
    }

    /**
     * Decrypt and extract the credential blob stored with this RK, if any.
     *
     * This should not be called if credBlobLen is zero for the RK.
     *
     * @param key Key for decryption
     * @param unwrapper Decryption object to use
     * @param targetBuffer Buffer into which to store the blob
     * @param targetOffset Offset at which to store the blob
     */
    public void unpackCredBlob(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        if (credBlob != null) {
            unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, CRED_BLOB_IV_OFFSET, IV_LEN);
            unwrapper.doFinal(credBlob, (short) 0, (short) credBlob.length,
                    targetBuffer, targetOffset);
        }
    }

    /**
     * Generate the Large Blob Key for this RK.
     *
     * @param key Key for generation
     * @param wrapper Cipher object to use in generation
     * @param targetBuffer Buffer into which to store the LBK
     * @param targetOffset Offset at which to store the LBK
     */
    public void emitLargeBlobKey(AESKey key, Cipher wrapper, byte[] targetBuffer, short targetOffset) {
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, LARGE_BLOB_IV_OFFSET, IV_LEN);
        wrapper.doFinal(publicKey, (short) 0, (short) 32,
                targetBuffer, targetOffset);
    }

    /**
     * Get the raw credential associated with this RK.
     *
     * @return Direct buffer containing wrapped Credential ID. Not for modification!
     */
    public byte[] getEncryptedCredentialID() {
        return credential;
    }

    /**
     * Get the length of the stored user ID.
     *
     * @return Length in bytes.
     */
    public short getUserIdLength() {
        return userIdLength;
    }

    /**
     * Get the length of the stored user name (not ID).
     *
     * @return Length in bytes.
     */
    public short getUserNameLength() {
        return userNameLength;
    }

    /**
     * Get the length of the stored Credential ID.
     *
     * @return Length in bytes.
     */
    public short getCredLen() {
        return (short) credential.length;
    }

    /**
     * Get the protection level of this credential.
     *
     * @return Level: 1, 2, or 3.
     */
    public byte getCredProtectLevel() {
        if (credProtectLevel < 0) {
            return (byte)(credProtectLevel * -1);
        }
        return credProtectLevel;
    }

    /**
     * Get whether the key is encrypted with the "high security" key
     *
     * @return true if high sec; false if low sec
     */
    public boolean getHighSecEncrypted() {
        return credProtectLevel < 0;
    }

    /**
     * Get whether this RK is (probably) for a unique Relying Party.
     *
     * @return True if no other RKs share this RP (probably); false otherwise
     */
    public boolean isUniqueRP() {
        return uniqueRP;
    }

    /**
     * Flag the RK as (probably) being for a unique Relying Party, or not.
     */
    public void setUniqueRP(boolean uniqueRP) {
        this.uniqueRP = uniqueRP;
    }

    /**
     * Get the length of the stored Relying Party ID.
     *
     * Note this might be truncated.
     *
     * @return Length in bytes.
     */
    public byte getRpIdLength() {
        return rpIdLength;
    }

    /**
     * Get the length of the stored arbitrary credBlob.
     *
     * Will return zero if no credBlob associated with this RK.
     *
     * @return Length in bytes.
     */
    public byte getCredBlobLen() {
        return this.credBlobLen;
    }
}
