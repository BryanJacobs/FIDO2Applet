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

    /**
     * Location in in-memory buffer of byte describing how much of the in-memory buffer is used
     */
    private static final byte OFFSET_MEMBUF_USED_SPACE = 0; // 2 bytes
    /**
     * Location in in-memory buffer of short describing how much flash is used
     */
    private static final byte OFFSET_FLASH_USED_SPACE = 2; // 2 bytes
    /**
     * Total in-memory buffer overhead of state keeping variables
     */
    private static final byte STATE_KEEPING_OVERHEAD = 4;

    /**
     * In-RAM buffer which is OUTSIDE the APDU buffer. Great to have for minimizing flash wear.
     */
    private final byte[] inMemoryBuffer;
    /**
     * Flash scratch buffer. A last resort for when there just isn't enough memory elsewhere.
     */
    private final byte[] flashBuffer;

    /**
     * Allow allocations in the portion of the APDU buffer behind the known read cursor (growing upwards)
     */
    public static final byte LOWER_APDU = (byte) 0x01;
    /**
     * Allow allocations in the portion of the APDU buffer beyond the end of the incoming request (growing downwards)
     */
    public static final byte UPPER_APDU = (byte) 0x02;
    /**
     * Allow allocations in the non-APDU buffer in memory
     */
    public static final byte MEMORY_BUFFER = (byte) 0x04;
    /**
     * Allow allocations in flash
     */
    public static final byte FLASH = (byte) 0x08;
    /**
     * Allow allocations in any location
     */
    public static final byte ANYWHERE = (byte) 0xFF;
    /**
     * Allow allocations anywhere that will not be clobbered by APDU writes
     */
    public static final byte NOT_APDU_BUFFER = (byte)(MEMORY_BUFFER | FLASH);
    /**
     * Allow allocations anywhere EXCEPT in the lower reaches of the APDU. This ensures that large APDU buffers with
     * small writes won't get clobbered.
     */
    public static final byte NOT_LOWER_APDU = (byte)(UPPER_APDU | MEMORY_BUFFER | FLASH);

    public BufferManager(short transientLen, short persistentLen) {
        inMemoryBuffer = JCSystem.makeTransientByteArray(transientLen, JCSystem.CLEAR_ON_DESELECT);
        flashBuffer = new byte[persistentLen];
        clear();
    }

    /**
     * Report on in-memory buffer sizing
     *
     * @return The number of bytes allocated to the in-memory non-APDU buffer
     */
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

    /**
     * Allows the state manager to use APDU lower byte ranges by telling it where the read cursor is.
     * Note that the write cursor may not be moved backwards: once the lower APDU buffer is expanded, it cannot shrink
     * until the APDU is entirely cleared and the buffer manager reset.
     *
     * @param apdu Request/response object
     * @param amt The position of the read cursor - all bytes below this will be made available for scratch memory
     */
    public void informAPDUBufferAvailability(APDU apdu, short amt) {
        if (amt > 0xFF) {
            amt = 0xFF;
        }
        final byte[] apduBuf = apdu.getBuffer();
        final short apduBufLen = getAPDUBufferLength(apduBuf);
        short apLowerSpace = (short)(0xFF & apduBuf[(short)(apduBufLen - 4)]);
        if (amt > apLowerSpace) {
            apduBuf[(short)(apduBufLen - 4)] = (byte) amt;
        }
    }

    private short getAPDUBufferLength(byte[] apduBuf) {
        final short apduBufferLength = (short) apduBuf.length;
        if (apduBufferLength < 0 || apduBufferLength > 8096) {
            // We can't really make use of huge buffers, and our offsets only work if the upper APDU buffer is
            // positioned at a reasonably small offset
            return 8095;
        }
        return apduBufferLength;
    }

    /**
     * Sets up the state manager to use upper+lower APDU ranges. Must be called prior to APDU memory allocations.
     *
     * @param apdu Request/response object
     */
    public void initializeAPDU(APDU apdu) {
        final byte[] apduBuf = apdu.getBuffer();
        final short apduBufferLength = getAPDUBufferLength(apduBuf);

        if (apdu.getIncomingLength() < (short)(apduBufferLength - 2)) {
            Util.setShort(apduBuf, (short)(apduBufferLength - 2), (short) 4); // the four state-keeping bytes
        }
        apduBuf[(short)(apduBufferLength - 3)] = 0x00;
        apduBuf[(short)(apduBufferLength - 4)] = 0x00;
    }

    /**
     * Gets an opaque memory allocation handle. Throws an exception if sufficient space is not available.
     *
     * @param apdu Request/response object
     * @param amt Number of bytes to allocate in a contiguous region
     * @param allowedLocations Bitfield representing where the memory may be placed
     *
     * @return Opaque handle which may be passed to other functions to get useful information or free
     */
    public short allocate(APDU apdu, short amt, byte allowedLocations) {
        final short lc = apdu.getIncomingLength();
        final byte[] apduBuf = apdu.getBuffer();
        final short apduBufLen = getAPDUBufferLength(apduBuf);
        short upperAPDUUsed = 0;
        if (lc < (short)(apduBufLen - 4)) {
            if ((allowedLocations & UPPER_APDU) != 0) {
                // Upper APDU buffer available potentially
                upperAPDUUsed = Util.getShort(apduBuf, (short) (apduBufLen - 2));
                short totalUpper = (short) (apduBufLen - lc);
                if ((short) (totalUpper - upperAPDUUsed) > amt) {
                    // We fit in the upper APDU buffer!
                    short offset = (short) (apduBufLen - upperAPDUUsed - amt - 1);
                    Util.setShort(apduBuf, (short) (apduBufLen - 2), (short) (upperAPDUUsed + amt));
                    return encodeUpperAPDUOffset(offset);
                }
            }

            if ((allowedLocations & LOWER_APDU) != 0) {
                short apLowerUsed = (short) (0xFF & apduBuf[(short) (apduBufLen - 3)]);
                short apLowerSpace = (short) (0xFF & apduBuf[(short) (apduBufLen - 4)]);
                if (amt <= (short) (apLowerSpace - apLowerUsed)) {
                    // Lower APDU buffer has room
                    if ((short) (apLowerUsed + amt) <= (short) (apduBufLen - upperAPDUUsed)) {
                        // ... and it doesn't overlap the already-allocated part of the upper APDU buffer
                        apduBuf[(short) (apduBufLen - 3)] += amt;
                        return encodeLowerAPDUOffset(apLowerUsed);
                    }
                }
            }
        }

        if ((allowedLocations & MEMORY_BUFFER) != 0) {
            short mbUsed = Util.getShort(inMemoryBuffer, OFFSET_MEMBUF_USED_SPACE);
            if (amt <= (short) (inMemoryBuffer.length - mbUsed)) {
                // Memory buffer has room
                Util.setShort(inMemoryBuffer, OFFSET_MEMBUF_USED_SPACE,
                        (short) (mbUsed + amt));
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

    /**
     * Release a previous allocation
     *
     * @param apdu Request/response object
     * @param handle Handle returned from allocate call
     * @param amt Size of allocation in bytes - must match what was passed to allocate call
     */
    public void release(APDU apdu, short handle, short amt) {
        if (handle < 0) {
            if (handle <= -12288) {
                Util.setShort(inMemoryBuffer, OFFSET_MEMBUF_USED_SPACE,
                        (short)(Util.getShort(inMemoryBuffer, OFFSET_MEMBUF_USED_SPACE) - amt));
                return;
            }
            final byte[] apduBuf = apdu.getBuffer();
            final short apduBufLen = getAPDUBufferLength(apduBuf);
            if (handle <= -256) {
                final short curUsed = Util.getShort(apduBuf, (short)(apduBufLen - 2));
                Util.setShort(apduBuf, (short)(apduBufLen - 2), (short)(curUsed - amt));
                return;
            }
            apduBuf[(short)(apduBufLen - 3)] -= amt;
            return;
        }
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE,
                (short)(Util.getShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE) - amt));
    }

    /**
     * Gets the buffer which contains the memory for a particular allocation handle
     *
     * @param apdu Request/response object
     * @param handle Result of a previous allocate call
     *
     * @return Byte array housing the allocated region
     */
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

    /**
     * Gets the offset within a buffer for a particular allocation handle
     *
     * @param apdu Request/response object
     * @param handle Result of a previous allocate call
     *
     * @return Offset within the byte array returned by getBufferForHandle at which the allocated memory begins
     */
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

    /**
     * Wipes internal state of the buffer manager, releasing all non-APDU objects. It's assumed the APDU will be cleared
     * between when this call is made and the next memory allocation is requested.
     */
    public void clear() {
        // We still keep our state variables in memory, so don't reset the used amount to zero...
        Util.setShort(inMemoryBuffer, OFFSET_MEMBUF_USED_SPACE, STATE_KEEPING_OVERHEAD);
        Util.setShort(inMemoryBuffer, OFFSET_FLASH_USED_SPACE, (short) 0);
    }
}
