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

    private static final byte OFFSET_MEMBUF_USED_SPACE = 0; // 1 byte
    private static final byte OFFSET_FLASH_USED_SPACE = 1; // 2 bytes
    private static final byte STATE_KEEPING_OVERHEAD = 3;

    private final byte[] inMemoryBuffer;
    private final byte[] flashBuffer;

    public static final byte LOWER_APDU = (byte) 0x01;
    public static final byte UPPER_APDU = (byte) 0x02;
    public static final byte MEMORY_BUFFER = (byte) 0x04;
    public static final byte FLASH = (byte) 0x08;
    public static final byte ANYWHERE = (byte) 0xFF;
    public static final byte NOT_APDU_BUFFER = (byte)(MEMORY_BUFFER | FLASH);
    public static final byte NOT_LOWER_APDU = (byte)(UPPER_APDU | MEMORY_BUFFER | FLASH);

    public BufferManager(byte transientLen, short persistentLen) {
        inMemoryBuffer = JCSystem.makeTransientByteArray( (short)(0xFF & transientLen), JCSystem.CLEAR_ON_DESELECT);
        flashBuffer = new byte[persistentLen];
        clear();
    }

    public short getTransientBufferSize() {
        return (short) inMemoryBuffer.length;
    }

    private short encodeLowerAPDUOffset(short offset) {
        // Lower APDU offsets are given in the range [-1,-257]
        return (short)(-1 * offset - 1);
    }

    private short encodeUpperAPDUOffset(short offset) {
        // Upper offsets are given in the range [-258,-12287]
        return (short)(-1 * offset - 257);
    }

    private short encodeMemoryBufferOffset(short offset) {
        // Memory offsets are given in the range [-12288, -infinity)
        return (short)(-1 * offset - 12288);
    }

    private short encodeFlashOffset(short offset) {
        // Flash buffer offsets are given raw
        return offset;
    }

    public void informAPDUBufferAvailability(APDU apdu, short amt) {
        if (amt > 0xFF) {
            amt = 0xFF;
        }
        final byte[] apduBuf = apdu.getBuffer();
        short apLowerSpace = (short)(0xFF & apduBuf[(short)(apduBuf.length - 4)]);
        if (amt > apLowerSpace) {
            apduBuf[(short)(apduBuf.length - 4)] = (byte) amt;
        }
    }

    public void initializeAPDU(APDU apdu) {
        final byte[] apduBuf = apdu.getBuffer();
        final short apduBufferLength = (short) apduBuf.length;

        if (apduBufferLength > 8096) {
            // Too long! We can't handle this.
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }

        if (apdu.getIncomingLength() < (short)(apduBufferLength - 2)) {
            Util.setShort(apduBuf, (short)(apduBufferLength - 2), (short) 4); // the four state-keeping bytes
        }
        apduBuf[(short)(apduBuf.length - 3)] = 0x00;
        apduBuf[(short)(apduBuf.length - 4)] = 0x00;
    }

    public short allocate(APDU apdu, short amt, byte allowedLocations) {
        final short lc = apdu.getIncomingLength();
        final byte[] apduBuf = apdu.getBuffer();
        final short apduBufLen = (short) apduBuf.length;
        short upperAPDUUsed = 0;
        if (lc < (short)(apduBufLen - 4)) {
            if ((allowedLocations & UPPER_APDU) != 0) {
                // Upper APDU buffer available potentially
                upperAPDUUsed = Util.getShort(apduBuf, (short) (apduBuf.length - 2));
                short totalUpper = (short) (apduBufLen - lc);
                if ((short) (totalUpper - upperAPDUUsed) >= amt) {
                    // We fit in the upper APDU buffer!
                    short offset = (short) (apduBufLen - upperAPDUUsed - amt - 1);
                    Util.setShort(apduBuf, (short) (apduBuf.length - 2), (short) (upperAPDUUsed + amt));
                    return encodeUpperAPDUOffset(offset);
                }
            }

            if ((allowedLocations & LOWER_APDU) != 0) {
                short apLowerUsed = (short) (0xFF & apduBuf[(short) (apduBuf.length - 3)]);
                short apLowerSpace = (short) (0xFF & apduBuf[(short) (apduBuf.length - 4)]);
                if (amt <= (short) (apLowerSpace - apLowerUsed)) {
                    // Lower APDU buffer has room
                    if ((short) (apLowerUsed + amt) <= (short) (apduBufLen - upperAPDUUsed)) {
                        // ... and it doesn't overlap the already-allocated part of the upper APDU buffer
                        apduBuf[(short) (apduBuf.length - 3)] += amt;
                        return encodeLowerAPDUOffset(apLowerUsed);
                    }
                }
            }
        }

        if ((allowedLocations & MEMORY_BUFFER) != 0) {
            short mbUsed = (short) (0xFF & inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE]);
            if (amt <= (short) (inMemoryBuffer.length - mbUsed)) {
                // Memory buffer has room
                inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] = (byte) (mbUsed + amt);
                return encodeMemoryBufferOffset(mbUsed);
            }
        }

        if ((allowedLocations & FLASH) != 0) {
            short apos = Util.getShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE);
            if (amt <= (short) (flashBuffer.length - apos)) {
                // Flash it is...
                Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE,
                        (short) (apos + amt));
                return encodeFlashOffset(apos);
            }
        }

        // No room anywhere...
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
        return 0; // unreachable, but javac doesn't realize that...
    }

    public void release(APDU apdu, short handle, short amt) {
        if (handle < 0) {
            if (handle <= -12288) {
                inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] -= amt;
                return;
            }
            final byte[] apduBuf = apdu.getBuffer();
            if (handle <= -256) {
                final short curUsed = Util.getShort(apduBuf, (short)(apduBuf.length - 2));
                Util.setShort(apduBuf, (short)(apduBuf.length - 2), (short)(curUsed - amt));
                return;
            }
            apduBuf[(short)(apduBuf.length - 3)] -= amt;
            return;
        }
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE,
                (short)(Util.getShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE) - amt));
    }

    public byte[] getBufferForHandle(APDU apdu, short handle) {
        if (handle < 0) {
            if (handle <= -12288) {
                return inMemoryBuffer;
            }
            // Both upper and lower APDU handles map here
            return apdu.getBuffer();
        }

        return flashBuffer;
    }

    public short getOffsetForHandle(short handle) {
        if (handle < 0) {
            if (handle <= -12288) {
                return (short)(handle * -1 - 12288);
            }
            if (handle < -256) {
                return (short)(-1 * handle - 257);
            }
            return (short)(-1 * handle - 1);
        }
        return handle;
    }

    public void clear() {
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE, (short) 0);
        // We still keep our state variables in memory, so don't reset the used amount to zero...
        inMemoryBuffer[OFFSET_MEMBUF_USED_SPACE] = STATE_KEEPING_OVERHEAD;
    }
}
