package us.q3q.fido2;

/**
 * Flash-stored counter for managing PIN retries. Can only be decremented, read, or reset.
 *
 * Attempts to avoid writing the same counter every time by rotating around an array.
 * This will be counterproductive (no write amplification, but runtime overhead) on a system with effective
 * wear leveling, but will greatly (up to 32x) extend the lifetime on systems without it.
 */
public final class PinRetryCounter {
    private final byte[] counters;
    private final byte defaultValue;

    public PinRetryCounter(byte defaultValue) {
        counters = new byte[64];
        this.defaultValue = defaultValue;
        counters[0] = defaultValue;
        for (short i = 1; i < counters.length; i++) {
            counters[i] = (byte)(defaultValue + 1);
        }
    }

    /**
     * Finds which counter is currently valid
     *
     * @return The index of the first "valid" (not set to defaultValue+1) counter in the array
     */
    private short getValidCounterIdx() {
        // Scan along array until we get to a counter that's valid
        short counterIdx = 0;
        for (counterIdx = 0; counterIdx < counters.length; counterIdx++) {
            if (counters[counterIdx] != (byte)(defaultValue + 1)) {
                break;
            }
        }
        return counterIdx;
    }

    /**
     * Prepare to decrement or fetch the retry counter
     *
     * @return A value that can be used to fetch, reset, or decrement the counter
     */
    public short prepareIndex() {
        return getValidCounterIdx();
    }

    public byte getRetryCount(short prepareResult) {
        return counters[prepareResult];
    }

    /**
     * Decrement the retry counter
     *
     * @param prepareResult The return value of the prepareToDecrement call
     */
    public void decrement(short prepareResult) {
        counters[prepareResult]--;
    }

    /**
     * Resets the counter back to its default value
     */
    public void reset(short prepareResult) {
        short nextCounterIdx = (short)(prepareResult + 1);
        if (nextCounterIdx >= counters.length) {
            // Wraparound
            nextCounterIdx = 0;
        }

        // Ordering is important: set up the new counter value, THEN clear out the newly-obsoleted one
        counters[nextCounterIdx] = defaultValue;
        counters[prepareResult] = (byte)(defaultValue + 1);
    }
}
