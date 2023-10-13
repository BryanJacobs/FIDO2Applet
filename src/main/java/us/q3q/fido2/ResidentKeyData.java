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
     * IV for encrypting the user info
     */
    private final byte[] userIdIV;
    /**
     * IV for encrypting the user name
     */
    private final byte[] userNameIV;
    /**
     * IV for encrypting the RP info (text, not a hash)
     */
    private final byte[] RPIV;
    /**
     * IV for encrypting the credential's public key
     */
    private final byte[] pubKeyIV;
    /**
     * IV for encrypting the credential's credBlob (opaque platform-driven storage)
     */
    private final byte[] credBlobIV;
    /**
     * IV for encrypting the credential's large blob data
     */
    private final byte[] largeBlobIV;
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
     */
    private final byte credProtectLevel;
    /**
     * Encrypted (with the device wrapping key) user ID field
     */
    private byte[] userId;
    /**
     * Length of the corresponding user ID
     */
    private short userIdLength;
    /**
     * Encrypted (with the device wrapping key) user Name field
     */
    private byte[] userName;
    /**
     * Length of the corresponding user name
     */
    private short userNameLength;
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
     * @param credProtectLevel Level of credential protection applied to this RK
     */
    public ResidentKeyData(RandomData random, AESKey key, Cipher wrapper,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength,
                           byte[] credBlobBuffer, short credBlobOffset, byte credBlobLen,
                           boolean uniqueRP, byte credProtectLevel) {
        userIdIV = new byte[IV_LEN];
        random.generateData(userIdIV, (short) 0, IV_LEN);
        userNameIV = new byte[IV_LEN];
        random.generateData(userNameIV, (short) 0, IV_LEN);
        RPIV = new byte[IV_LEN];
        random.generateData(RPIV, (short) 0, IV_LEN);
        pubKeyIV = new byte[IV_LEN];
        random.generateData(pubKeyIV, (short) 0, IV_LEN);
        largeBlobIV = new byte[IV_LEN];
        random.generateData(largeBlobIV, (short) 0, IV_LEN);

        if (credBlobLen > 0) {
            credBlobIV = new byte[IV_LEN];
            random.generateData(credBlobIV, (short) 0, IV_LEN);
            credBlob = new byte[encryptableLength(credBlobLen)];
            wrapper.init(key, Cipher.MODE_ENCRYPT, credBlobIV, (short) 0, (short) credBlobIV.length);
            wrapper.doFinal(credBlobBuffer, credBlobOffset, (short) credBlob.length,
                    credBlob, (short) 0);
            this.credBlobLen = credBlobLen;
        } else {
            credBlob = null;
            credBlobIV = null;
            this.credBlobLen = 0;
        }

        publicKey = new byte[publicKeyLength];
        wrapper.init(key, Cipher.MODE_ENCRYPT, pubKeyIV, (short) 0, (short) pubKeyIV.length);
        wrapper.doFinal(publicKeyBuffer, publicKeyOffset, publicKeyLength,
                publicKey, (short) 0);

        this.uniqueRP = uniqueRP;
        this.credProtectLevel = credProtectLevel;
    }

    /**
     * Sets the actual Credential ID stored by this RK.
     *
     * @param credBuffer Buffer containing ready-to-use Credential ID
     * @param credOffset Offset of credential within given buffer
     * @param credLen Length of credential
     */
    public void setEncryptedCredential(byte[] credBuffer, short credOffset, short credLen) {
        if (credential != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        this.credential = new byte[credLen];
        Util.arrayCopy(credBuffer, credOffset,
                this.credential, (short) 0, credLen);
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
        wrapper.init(key, Cipher.MODE_ENCRYPT, RPIV, (short) 0, (short) RPIV.length);
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
                        byte[] userIdBuffer, short userIdOffset, short userIdLength,
                        byte[] userNameBuffer, short userNameOffset, short userNameLength) {
        final short newUserIdBufferLength = encryptableLength(userIdLength);
        if (userId == null || newUserIdBufferLength > userId.length) {
            userId = new byte[encryptableLength(userIdLength)];
        }
        Util.arrayCopy(userIdBuffer, userIdOffset,
                userId, (short) 0, userIdLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, userIdIV, (short) 0, (short) userIdIV.length);
        wrapper.doFinal(userId, (short) 0, (short) userId.length,
                userId, (short) 0);
        this.userIdLength = userIdLength;

        if (userNameLength > 64) {
            // let's truncate the user name
            userNameLength = 64;
        }

        short newUserNameBufferLength = encryptableLength(userNameLength);
        if (userName == null || newUserNameBufferLength > userName.length) {
            userName = new byte[encryptableLength(userNameLength)];
        }
        Util.arrayCopy(userNameBuffer, userNameOffset,
                userName, (short) 0, userNameLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, userNameIV, (short) 0, (short) userNameIV.length);
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
        unwrapper.init(key, Cipher.MODE_DECRYPT, userIdIV, (short) 0, (short) userIdIV.length);
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
        unwrapper.init(key, Cipher.MODE_DECRYPT, userNameIV, (short) 0, (short) userNameIV.length);
        unwrapper.doFinal(userName, (short) 0, (short) userName.length,
                targetBuffer, targetOffset);
    }

    /**
     * Decrypt and extract the public key for this RK.
     *
     * @param key Key for decryption
     * @param unwrapper Decryption object to use
     * @param targetBuffer Buffer into which to store the pubKey
     * @param targetOffset Offset at which to store the pubKey
     */
    public void unpackPublicKey(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, pubKeyIV, (short) 0, (short) pubKeyIV.length);
        unwrapper.doFinal(publicKey, (short) 0, (short) publicKey.length,
                targetBuffer, targetOffset);
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
        unwrapper.init(key, Cipher.MODE_DECRYPT, RPIV, (short) 0, (short) RPIV.length);
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
            unwrapper.init(key, Cipher.MODE_DECRYPT, credBlobIV, (short) 0, (short) credBlobIV.length);
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
        wrapper.init(key, Cipher.MODE_ENCRYPT, largeBlobIV, (short) 0, (short) largeBlobIV.length);
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
        return credProtectLevel;
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
