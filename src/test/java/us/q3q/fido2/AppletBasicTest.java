package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Example (only example) unit tests with jcardsim
 */
public class AppletBasicTest {

    CardSimulator simulator;
    AID appletAID = AIDUtil.create("A0000006472F0001");
    AID randoAID = AIDUtil.create("F100900001");
    AID randoLongAID = AIDUtil.create("F100900001AAAAAAAAAAAA");

    @BeforeEach
    public void setupApplet() {
        simulator = new CardSimulator();

        simulator.installApplet(appletAID, FIDO2Applet.class);

        simulator.selectApplet(appletAID);
    }

    private ResponseAPDU sendCTAP(String hexCommand) {
        int[] bparams = new int[hexCommand.length() / 2];
        for (int i = 0; i < bparams.length; i++) {
            bparams[i] = ((Character.digit(hexCommand.charAt(i*2), 16) << 4)
                    + Character.digit(hexCommand.charAt(i*2+1), 16));
        }
        return sendCTAP(bparams);
    }

    private ResponseAPDU send(byte[] bparams) {
        CommandAPDU commandAPDU = new CommandAPDU(bparams);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        ArrayList<ResponseAPDU> prevResponses = new ArrayList<>();
        int totalResponseLen = response.getNr();
        prevResponses.add(response);
        while (response.getSW() >= ISO7816.SW_BYTES_REMAINING_00 && response.getSW() < ISO7816.SW_BYTES_REMAINING_00 + 256 && totalResponseLen < 65537) {
            // Chaining... chained response...
            CommandAPDU nextADPU = new CommandAPDU(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00});
            response = simulator.transmitCommand(nextADPU);
            prevResponses.add(response);
            totalResponseLen += response.getData().length;
        }

        byte[] combinedBB = new byte[totalResponseLen + 2];
        ResponseAPDU lastResponse = prevResponses.get(prevResponses.size() - 1);

        int off = 0;
        for (int i = 0; i < prevResponses.size(); i++) {
            byte[] b = prevResponses.get(i).getData();
            for (int j = 0; j < b.length; j++) {
                combinedBB[off++] = b[j];
            }
        }

        combinedBB[off++] = (byte) lastResponse.getSW1();
        combinedBB[off++] = (byte) lastResponse.getSW2();

        return new ResponseAPDU(combinedBB);
    }

    private ResponseAPDU send(int... params) {
        byte[] bparams = new byte[params.length];
        for (int i = 0; i < params.length; i++) {
            bparams[i] = (byte) params[i];
        }

        return send(bparams);
    }

    private ResponseAPDU sendCTAP(int... vals) {
        boolean shortLen = vals.length <= 255;
        int[] framedVals = new int[vals.length + (shortLen ? 6 : 7)]; // Hmm, why isn't this 8 for extended length?
        framedVals[0] = 0x80;
        framedVals[1] = 0x10;
        framedVals[2] = 0x00;
        framedVals[3] = 0x00;
        if (shortLen) {
            framedVals[4] = (byte) vals.length;
        } else {
            framedVals[4] = 0x00;
            framedVals[5] = (vals.length & 0xFF00) >> 8;
            framedVals[6] = vals.length & 0x00FF;
        }
        System.arraycopy(vals, 0, framedVals, shortLen ? 5 : 7, vals.length);
        framedVals[framedVals.length - 1] = 0x00;
        return send(framedVals);
    }

    @Test
    public void checkIncorrectCLA() {
        ResponseAPDU response = send(0x00, 0x09, 0x00, 0x00);

        assertEquals(ISO7816.SW_CLA_NOT_SUPPORTED, response.getSW());
    }

    @Test
    public void checkIncorrectINS() {
        ResponseAPDU response = send(0x80, 0x01, 0x00, 0x00);

        assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, response.getSW());
    }

    @Test
    public void checkIncorrectP1() {
        ResponseAPDU response = send(0x80, 0x10, 0x01, 0x00);

        assertEquals(ISO7816.SW_INCORRECT_P1P2, response.getSW());
    }

    @Test
    public void checkIncorrectP2() {
        ResponseAPDU response = send(0x80, 0x10, 0x00, 0x01);

        assertEquals(ISO7816.SW_INCORRECT_P1P2, response.getSW());
    }

    @Test
    public void checkUnknownCTAPCommand() {
        ResponseAPDU response = sendCTAP(0x99);

        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        byte[] data = response.getData();
        assertEquals(1, data.length);
        assertEquals(FIDOConstants.CTAP1_ERR_INVALID_COMMAND, data[0]);
    }

    @Test
    public void checkVersionInSelectionResponse() {
        byte[] resp = simulator.selectAppletWithResult(appletAID);

        short recvdStatus = (short) (resp[resp.length - 2] * 256 + resp[resp.length - 1]);

        assertEquals(ISO7816.SW_NO_ERROR, recvdStatus);

        byte[] respWithoutStatus = new byte[resp.length-2];
        System.arraycopy(resp, 0, respWithoutStatus, 0, resp.length-2);
        assertEquals("FIDO_2_0", new String(respWithoutStatus));
    }

    @Test
    public void checkIgnoreSelectingIncorrectAID() {
        byte[] resp = simulator.selectAppletWithResult(appletAID);
        short recvdStatus = (short) (resp[resp.length - 2] * 256 + resp[resp.length - 1]);

        assertEquals(ISO7816.SW_NO_ERROR, recvdStatus);

        ResponseAPDU responseAPDU = send(AIDUtil.select(randoAID));
        assertEquals(ISO7816.SW_FILE_NOT_FOUND, responseAPDU.getSW());
    }

    @Test
    public void checkIgnoreSelectingIncorrectLongAID() {
        byte[] resp = simulator.selectAppletWithResult(appletAID);
        short recvdStatus = (short) (resp[resp.length - 2] * 256 + resp[resp.length - 1]);

        assertEquals(ISO7816.SW_NO_ERROR, recvdStatus);

        ResponseAPDU responseAPDU = send(AIDUtil.select(randoLongAID));
        assertEquals(ISO7816.SW_FILE_NOT_FOUND, responseAPDU.getSW());
    }

}
