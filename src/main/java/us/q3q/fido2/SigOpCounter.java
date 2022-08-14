package us.q3q.fido2;

import javacard.framework.JCSystem;

/**
 * 32-bit always-increasing counter that avoids writing to the same flash location too often
 *
 * Uses 67 bytes of flash to provide a 32-bit counter where the most-written byte is written 256
 * times in a row, but only takes 1/64 of the overall write load.
 */
public class SigOpCounter {
    private final byte[] firstBytes;
    private final byte[] lastBytes;

    public SigOpCounter() {
        firstBytes = new byte[3];
        lastBytes = new byte[64];
    }

    /**
     * Atomically increase the counter value
     *
     * @return false if the counter has hit max - true otherwise
     */
    public boolean increment() {
        boolean ok = false;

        JCSystem.beginTransaction();
        short lbIdx = (short)(0x3F & firstBytes[2]);
        try {
            if (lastBytes[lbIdx] == (byte) 0xFF) {
                // Increase the higher-order bytes and move to next lower-order byte slot
                if (firstBytes[2] == (byte) 0xFF) {
                    if (firstBytes[1] == (byte) 0xFF) {
                        if (firstBytes[0] == (byte) 0xFF) {
                            // Completely full up.
                            return false;
                        }
                        firstBytes[0]++;
                        firstBytes[1] = 0;
                    } else {
                        firstBytes[1]++;
                    }
                    firstBytes[2] = 0;
                } else {
                    firstBytes[2]++;
                }
                lastBytes[(short)(0x3F & firstBytes[2])] = 0;
            } else {
                // Straightforward increase of lower-order byte
                lastBytes[lbIdx]++;
            }
            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        return true;
    }

    /**
     * Packs counter as a 32-bit (4 byte) integer into the output
     *
     * @param outBuf Buffer into which to encode counter
     * @param outOffset Offset at which to start writing counter
     *
     * @return Write index into buffer after encoding counter
     */
    public short pack(byte[] outBuf, short outOffset) {
        outBuf[outOffset++] = firstBytes[0];
        outBuf[outOffset++] = firstBytes[1];
        outBuf[outOffset++] = firstBytes[2];
        outBuf[outOffset++] = lastBytes[(short)(0x3F & firstBytes[2])];
        return outOffset;
    }

    /**
     * Resets counter for new use. Does not start its own transaction - use within an existing one!
     */
    public void clear() {
        firstBytes[0] = 0;
        firstBytes[1] = 0;
        firstBytes[2] = 0;
        lastBytes[0] = 0; // other lastByte entries will be zeroed again when we reach them in the natural course
    }
}
