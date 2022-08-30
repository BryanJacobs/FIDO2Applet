package us.q3q.fido2;

import javacard.framework.*;

/**
 * A class for managing the awkwardness of preferring RAM to flash on very resource-constrained devices.
 *
 * Will allocate space from, in descending order of priority:
 * - The upper reaches of the APDU buffer, beyond the incoming request length
 * - The lower bounds of the APDU buffer, behind the current read index
 * - A TRANSIENT_DESELECT buffer
 * - Flash storage
 *
 * Allocations return opaque handles that need to be decoded to byte array references and offsets.
 * Memory can only be freed in the reverse order it is acquired - no fragmentation allowed and only a few
 * bytes of management overhead.
 */
public final class BufferManager {

    private static final byte OFFSET_APDU_LOWER_SPACE = 0; // 1 byte
    private static final byte OFFSET_APDU_USED_SPACE = 1; // 1 byte
    private static final byte OFFSET_MEMBUF_USED_SPACE = 2; // 1 byte
    private static final byte OFFSET_FLASH_USED_SPACE = 3; // 2 bytes
    private static final byte STATE_KEEPING_OVERHEAD = 5;

    private static final short APDU_OFFSET_UPPER_APDU_USED_SPACE = 0xFF; // Offset WITHIN THE APDU BUFFER

    private final byte[] inMemoryBuffer;
    private final byte[] flashBuffer;

    public BufferManager(byte transientLen, short persistentLen) {
        inMemoryBuffer = JCSystem.makeTransientByteArray( (short)(0xFF & transientLen), JCSystem.CLEAR_ON_DESELECT);
        flashBuffer = new byte[persistentLen];
        clear();
    }

    private short encodeLowerAPDUOffset(short offset) {
        // Lower APDU offsets are given in the range [-1,-257]
        return (short)(-1 * offset - 1);
    }

    private short encodeUpperAPDUOffset(short offset) {
        // Upper offsets are given in the range [-258,-507]
        return (short)(-1 * offset - 257);
    }

    private short encodeMemoryBufferOffset(short offset) {
        // Memory offsets are given in the range [-4096, -infinity)
        return (short)(-1 * offset - 4096);
    }

    private short encodeFlashOffset(short offset) {
        // Flash buffer offsets are given raw
        return offset;
    }

    public void informAPDUBufferAvailability(short amt) {
        if (amt > 0xFF) {
            amt = 0xFF;
        }
        if (amt > inMemoryBuffer[OFFSET_APDU_LOWER_SPACE]) {
            inMemoryBuffer[OFFSET_APDU_LOWER_SPACE] = (byte) amt;
        }
    }

    public void initializeAPDU(APDU apdu) {
        if (apdu.getIncomingLength() < 256) {
            apdu.getBuffer()[APDU_OFFSET_UPPER_APDU_USED_SPACE] = 0x01; // one byte used for this state-keeping
        }
    }

    public short allocate(APDU apdu, short amt, boolean avoidAPDUBuffer) {
        if (!avoidAPDUBuffer) {
            short lc = apdu.getIncomingLength();
            short upperAPDUUsed = 0;
            if (lc < 256) {
                // Upper APDU buffer available potentially
                byte[] apduBuf = apdu.getBuffer();
                upperAPDUUsed = (short)(0xFF & apduBuf[APDU_OFFSET_UPPER_APDU_USED_SPACE]);
                short totalUpper = (short)(255 - lc);
                if ((short)(totalUpper - upperAPDUUsed) >= amt) {
                    // We fit in the upper APDU buffer!
                    short offset = (short)(255 - upperAPDUUsed - amt);
                    apduBuf[APDU_OFFSET_UPPER_APDU_USED_SPACE] = (byte)(upperAPDUUsed + amt);
                    return encodeUpperAPDUOffset(offset);
                }
            }

            short apLowerUsed = (short)(0xFF & inMemoryBuffer[OFFSET_APDU_USED_SPACE]);
            if (amt <= (short)((0xFF & inMemoryBuffer[OFFSET_APDU_LOWER_SPACE]) - apLowerUsed)) {
                // Lower APDU buffer has room
                if ((short)(apLowerUsed + amt) <= (short)(256 - upperAPDUUsed)) {
                    // ... and it doesn't overlap the already-allocated part of the upper APDU buffer
                    inMemoryBuffer[OFFSET_APDU_USED_SPACE] += amt;
                    return encodeLowerAPDUOffset(apLowerUsed);
                }
            }
        }

        short mbUsed = (short)(0xFF & inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE]);
        if (amt <= (short)(inMemoryBuffer.length - mbUsed)) {
            // Memory buffer has room
            inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] = (byte)(mbUsed + amt);
            return encodeMemoryBufferOffset(mbUsed);
        }

        short apos = Util.getShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE);
        if (amt <= (short)(flashBuffer.length - apos)) {
            // Flash it is...
            Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE,
                    (short)(apos + amt));
            return encodeFlashOffset(apos);
        }

        // No room anywhere...
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
        return 0; // unreachable, but javac doesn't realize that...
    }

    public void release(APDU apdu, short handle, short amt) {
        if (handle < 0) {
            if (handle <= -4096) {
                inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] -= amt;
                return;
            }
            if (handle <= -256) {
                apdu.getBuffer()[APDU_OFFSET_UPPER_APDU_USED_SPACE] -= amt;
                return;
            }
            inMemoryBuffer[OFFSET_APDU_USED_SPACE] -= amt;
            return;
        }
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE,
                (short)(Util.getShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE) - amt));
    }

    public byte[] getBufferForHandle(APDU apdu, short handle) {
        if (handle < 0) {
            if (handle <= -4096) {
                return inMemoryBuffer;
            }
            // Both upper and lower APDU handles map here
            return apdu.getBuffer();
        }

        return flashBuffer;
    }

    public short getOffsetForHandle(short handle) {
        if (handle < 0) {
            if (handle <= -4096) {
                return (short)(handle * -1 - 4096);
            }
            if (handle < -256) {
                return (short)(-1 * handle - 257);
            }
            return (short)(-1 * handle - 1);
        }
        return handle;
    }

    public void clear() {
        inMemoryBuffer[OFFSET_APDU_USED_SPACE] = 0;
        inMemoryBuffer[OFFSET_APDU_LOWER_SPACE] = 0;
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE, (short) 0);
        // We still keep our state variables in memory, so don't reset those to zero...
        inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] = STATE_KEEPING_OVERHEAD;
    }
}
