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
 * appropiately protected.
 */
public class ResidentKeyData {
    /**
     * How long, in bytes, initialization vectors within this class are
     */
    private static final short IV_LEN = 16;

    /**
     * IV for encrypting the user info
     */
    private final byte[] userIV;
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
     * Contains the four-byte signature counter at the time of RK creation.
     * This allows tracking which credential was most recently created.
     */
    private final byte[] counter;
    /**
     * Encrypted (with the device wrapping key) user ID field
     */
    private byte[] userId;
    /**
     * Length of the corresponding user IDs
     */
    private short userIdLength;
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

    public ResidentKeyData(RandomData random, AESKey key, Cipher wrapper, SigOpCounter creationCounter,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength,
                           byte[] credBlobBuffer, short credBlobOffset, byte credBlobLen,
                           boolean uniqueRP, byte credProtectLevel) {
        userIV = new byte[IV_LEN];
        random.generateData(userIV, (short) 0, IV_LEN);
        RPIV = new byte[IV_LEN];
        random.generateData(RPIV, (short) 0, IV_LEN);
        pubKeyIV = new byte[IV_LEN];
        random.generateData(pubKeyIV, (short) 0, IV_LEN);
        credBlobIV = new byte[IV_LEN];
        random.generateData(credBlobIV, (short) 0, IV_LEN);
        largeBlobIV = new byte[IV_LEN];
        random.generateData(largeBlobIV, (short) 0, IV_LEN);

        counter = new byte[4];
        creationCounter.pack(counter, (short) 0);

        if (credBlobLen > 0) {
            credBlob = new byte[encryptableLength(credBlobLen)];
            wrapper.init(key, Cipher.MODE_ENCRYPT, credBlobIV, (short) 0, (short) credBlobIV.length);
            wrapper.doFinal(credBlobBuffer, credBlobOffset, (short) credBlob.length,
                    credBlob, (short) 0);
            this.credBlobLen = credBlobLen;
        } else {
            credBlob = null;
            this.credBlobLen = 0;
        }

        publicKey = new byte[publicKeyLength];
        wrapper.init(key, Cipher.MODE_ENCRYPT, pubKeyIV, (short) 0, (short) pubKeyIV.length);
        wrapper.doFinal(publicKeyBuffer, publicKeyOffset, publicKeyLength,
                publicKey, (short) 0);

        this.uniqueRP = uniqueRP;
        this.credProtectLevel = credProtectLevel;
    }

    public void setEncryptedCredential(byte[] credBuffer, short credOffset, short credLen) {
        if (credential != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        this.credential = new byte[credLen];
        Util.arrayCopyNonAtomic(credBuffer, credOffset,
                this.credential, (short) 0, credLen);
    }

    /**
     * We can only encrypt/decrypt in 16-byte chunks
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

    public void setUser(AESKey key, Cipher wrapper, byte[] userIdBuffer, short userIdOffset, short userIdLength) {
        short newUserIdBufferLength = encryptableLength(userIdLength);
        if (userId == null || newUserIdBufferLength > userId.length) {
            userId = new byte[encryptableLength(userIdLength)];
        }
        Util.arrayCopy(userIdBuffer, userIdOffset,
                userId, (short) 0, (short) userId.length);
        wrapper.init(key, Cipher.MODE_ENCRYPT, userIV, (short) 0, (short) userIV.length);
        wrapper.doFinal(userId, (short) 0, (short) userId.length,
                userId, (short) 0);
        this.userIdLength = userIdLength;
    }

    public void unpackUserID(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, userIV, (short) 0, (short) userIV.length);
        unwrapper.doFinal(userId, (short) 0, (short) userId.length,
                targetBuffer, targetOffset);
    }

    public void unpackPublicKey(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, pubKeyIV, (short) 0, (short) pubKeyIV.length);
        unwrapper.doFinal(publicKey, (short) 0, (short) publicKey.length,
                targetBuffer, targetOffset);
    }

    public void unpackRpId(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, RPIV, (short) 0, (short) RPIV.length);
        unwrapper.doFinal(rpId, (short) 0, (short) rpId.length,
                targetBuffer, targetOffset);
    }

    public void unpackCredBlob(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, credBlobIV, (short) 0, (short) credBlobIV.length);
        unwrapper.doFinal(credBlob, (short) 0, (short) credBlob.length,
                targetBuffer, targetOffset);
    }

    public void emitLargeBlobKey(AESKey key, Cipher wrapper, byte[] targetBuffer, short targetOffset) {
        wrapper.init(key, Cipher.MODE_ENCRYPT, largeBlobIV, (short) 0, (short) largeBlobIV.length);
        wrapper.doFinal(publicKey, (short) 0, (short) 32,
                targetBuffer, targetOffset);
    }

    public byte[] getCounter() {
        return counter;
    }

    public byte[] getEncryptedCredentialID() {
        return credential;
    }

    public short getUserIdLength() {
        return userIdLength;
    }

    public short getCredLen() {
        return (short) credential.length;
    }

    public byte getCredProtectLevel() {
        return credProtectLevel;
    }

    public boolean isUniqueRP() {
        return uniqueRP;
    }

    public void setUniqueRP(boolean uniqueRP) {
        this.uniqueRP = uniqueRP;
    }

    public byte getRpIdLength() {
        return rpIdLength;
    }

    public byte getCredBlobLen() {
        return this.credBlobLen;
    }
}
