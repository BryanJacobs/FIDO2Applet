package us.q3q.fido2;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Provides in-memory state in a maximally compact way
 */
public final class TransientStorage {
    /**
     * One-byte-long temporary values
     */
    private final byte[] tempBytes;
    private static final byte IDX_PIN_RETRIES_SINCE_RESET = 0; // 1 byte
    /**
     * Used for storing found indices in searches
     */
    private static final byte IDX_TEMP_BUF_IDX_STORAGE = 1; // 2 bytes
    /**
     * Used for storing found lengths in searches
     */
    private static final byte IDX_TEMP_BUF_IDX_LEN = 3; // 1 byte
    /**
     * A permissions bitfield for the currently set PIN token
     *
     * The lower six bits are used for FIDO 2 permissions. The two most significant bits encode the PIN protocol number.
     */
    private static final byte IDX_PIN_PROTOCOL_NUMBER_AND_PERMISSIONS = 4; // 1 byte
    /**
     * Cred or RP iteration index, used when iterating through creds or RPs with credManagement commands
     * Disambiguated by the most significant bit: 1 for RPs, 0 for creds
     */
    private static final byte IDX_CRED_RP_ITERATION_POINTER = 5; // 1 byte
    /**
     * Index of next credential to consider when iterating through assertions with getNextAssertion commands
     */
    private static final byte IDX_ASSERT_ITERATION_POINTER = 6; // 1 byte
    /**
     * When writing an overlong response using chained APDUs, stores the position we're up to in the outgoing buffer
     */
    private static final byte IDX_CONTINUATION_OUTGOING_WRITE_OFFSET = 7; // 2 bytes
    /**
     * When writing an overlong response using chained APDUs, stores the remaining bytes in the outgoing buffer
     */
    private static final byte IDX_CONTINUATION_OUTGOING_REMAINING = 9; // 2 bytes
    /**
     * When reading an overlong incoming request using chained APDUs, stores the fill level of the incoming buffer
     */
    private static final byte IDX_CHAINING_INCOMING_READ_OFFSET = 11; // 2 bytes
    /**
     * Giant boolean bitfield that holds all the BOOL_IDX variables below
     */
    private static final byte IDX_BOOLEAN_OMNIBUS = 13; // 1 byte
    /**
     * How many bytes long the temp storage should be
     */
    private static final byte NUM_RESET_BYTES = 14;

    // boolean bit indices held in BOOLEAN_OMNIBUS byte above
    /**
     * set when authenticator key initialized
     */
    private static final byte BOOL_IDX_RESET_PLATFORM_KEY_SET = 0;
    /**
     * set if the "up" (User Presence) option is enabled
     */
    private static final byte BOOL_IDX_OPTION_UP = 1;
    /**
     * set if the "uv" (User Validation) option is enabled
     */
    private static final byte BOOL_IDX_OPTION_UV = 2;
    /**
     * set if the "rk" (Resident Key) option is enabled
     */
    private static final byte BOOL_IDX_OPTION_RK = 3;
    /**
     * For reset "protection" feature, checks if a reset request has been received since the last authenticator powerup
     */
    private static final byte BOOL_IDX_RESET_RECEIVED_SINCE_POWERON = 4;
    /**
     * Set to true when the authenticator app is fully disabled until next reselect
     */
    private static final byte BOOL_IDX_AUTHENTICATOR_DISABLED = 5;

    public TransientStorage() {
        // Pin-retries-since-reset counter, which must be cleared on RESET, not on deselect, is stored in this array
        tempBytes = JCSystem.makeTransientByteArray(NUM_RESET_BYTES, JCSystem.CLEAR_ON_RESET);
    }

    public void fullyReset() {
        // FULL reset includes pin-retry-since-reset counter
        Util.arrayFillNonAtomic(tempBytes, (short) 0, NUM_RESET_BYTES, (byte) 0x00);
    }

    private boolean getBoolByIdx(byte idx) {
        return (byte)((tempBytes[IDX_BOOLEAN_OMNIBUS] & (1 << idx))) != 0;
    }

    private void setBoolByIdx(byte idx, boolean val) {
        if (val) {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte)(tempBytes[IDX_BOOLEAN_OMNIBUS] | (1 << idx));
        } else {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte)(tempBytes[IDX_BOOLEAN_OMNIBUS] & ~(1 << idx));
        }
    }

    public boolean authenticatorDisabled() {
        return getBoolByIdx(BOOL_IDX_AUTHENTICATOR_DISABLED);
    }

    public void disableAuthenticator() {
        setBoolByIdx(BOOL_IDX_AUTHENTICATOR_DISABLED, true);
    }

    public void clearIterationPointers() {
        tempBytes[IDX_CRED_RP_ITERATION_POINTER] = 0;
    }

    public void clearAssertIterationPointer() {
        tempBytes[IDX_ASSERT_ITERATION_POINTER] = 0;
    }

    public short getChainIncomingReadOffset() {
        return Util.getShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET);
    }

    public void resetChainIncomingReadOffset() {
        Util.setShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET, (short) 0);
    }

    public void increaseChainIncomingReadOffset(short numBytes) {
        Util.setShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET,
                (short)(Util.getShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET) + numBytes));
    }

    public byte getPinTriesSinceReset() {
        return tempBytes[IDX_PIN_RETRIES_SINCE_RESET];
    }

    public void clearPinTriesSinceReset() {
        tempBytes[IDX_PIN_RETRIES_SINCE_RESET] = 0;
    }

    public void incrementPinTriesSinceReset() {
        tempBytes[IDX_PIN_RETRIES_SINCE_RESET]++;
    }

    public void setPlatformKeySet() {
        setBoolByIdx(BOOL_IDX_RESET_PLATFORM_KEY_SET, true);
    }

    public boolean isPlatformKeySet() {
        return getBoolByIdx(BOOL_IDX_RESET_PLATFORM_KEY_SET);
    }

    public void clearOnDeselect() {
        // Note: fill starts from index 1, skipping the pin-retries-since-reset counter
        Util.arrayFillNonAtomic(tempBytes, (short) 1, NUM_RESET_BYTES, (byte) 0x00);
    }

    public void readyStoredVars() {
        setStoredVars((short) 0, (byte) -1);
    }

    public void setStoredVars(short idx, byte len) {
        Util.setShort(tempBytes, IDX_TEMP_BUF_IDX_STORAGE, idx);
        tempBytes[IDX_TEMP_BUF_IDX_LEN] = len;
    }

    public short getStoredIdx() {
        return Util.getShort(tempBytes, IDX_TEMP_BUF_IDX_STORAGE);
    }

    public byte getStoredLen() {
        return tempBytes[IDX_TEMP_BUF_IDX_LEN];
    }

    public void defaultOptions() {
        setBoolByIdx(BOOL_IDX_OPTION_UP, true);
        setBoolByIdx(BOOL_IDX_OPTION_UV, false);
        setBoolByIdx(BOOL_IDX_OPTION_RK, false);
    }

    public boolean hasRKOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_RK);
    }

    public void setRKOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_RK, val);
    }

    public boolean hasUPOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_UP);
    }

    public void setUPOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_UP, val);
    }

    public boolean hasUVOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_UV);
    }

    public void setUVOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_UV, val);
    }

    public byte getAssertIterationPointer() {
        return tempBytes[IDX_ASSERT_ITERATION_POINTER];
    }

    public void setAssertIterationPointer(byte val) {
        tempBytes[IDX_ASSERT_ITERATION_POINTER] = val;
    }

    public void setOutgoingContinuation(short offset, short remaining) {
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET, offset);
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING, remaining);
    }

    public void clearOutgoingContinuation() {
        setOutgoingContinuation((short) 0, (short) 0);
    }

    public short getOutgoingContinuationOffset() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET);
    }

    public short getOutgoingContinuationRemaining() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING);
    }

    public boolean isResetCommandSentSincePowerOn() {
        return getBoolByIdx(BOOL_IDX_RESET_RECEIVED_SINCE_POWERON);
    }

    public void setResetCommandSentSincePowerOn() {
        setBoolByIdx(BOOL_IDX_RESET_RECEIVED_SINCE_POWERON, true);
    }

    public byte getRPIterationPointer() {
        if ((tempBytes[IDX_CRED_RP_ITERATION_POINTER] & 0x80) == 0) {
            return 0x00;
        }
        return (byte)(tempBytes[IDX_CRED_RP_ITERATION_POINTER] & 0x7F);
    }

    public void setRPIterationPointer(byte val) {
        tempBytes[IDX_CRED_RP_ITERATION_POINTER] = (byte)(val | 0x80);
    }

    public byte getCredIterationPointer() {
        if ((tempBytes[IDX_CRED_RP_ITERATION_POINTER] & 0x80) != 0) {
            return 0x00;
        }
        return tempBytes[IDX_CRED_RP_ITERATION_POINTER];
    }

    public void setCredIterationPointer(byte val) {
        tempBytes[IDX_CRED_RP_ITERATION_POINTER] = val;
    }

    public void setPinProtocolInUse(byte pinProtocol, byte pinPermissions) {
        tempBytes[IDX_PIN_PROTOCOL_NUMBER_AND_PERMISSIONS] = (byte)((pinProtocol << 6) | (pinPermissions & 0x3F));
    }

    public byte getPinProtocolInUse() {
        return (byte)((tempBytes[IDX_PIN_PROTOCOL_NUMBER_AND_PERMISSIONS] & 0xC0) >> 6);
    }

    public byte getPinPermissions() {
        return (byte)(tempBytes[IDX_PIN_PROTOCOL_NUMBER_AND_PERMISSIONS] & 0x3F);
    }
}
