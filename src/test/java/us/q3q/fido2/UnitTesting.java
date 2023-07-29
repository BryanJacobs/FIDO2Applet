package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import us.q3q.fido2.FIDO2Applet;
import us.q3q.fido2.FIDOConstants;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Example (only example) unit tests with jcardsim
 */
public class UnitTesting {

    CardSimulator simulator;
    AID appletAID = AIDUtil.create("F000000001");

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

    private ResponseAPDU send(int... params) {
        byte[] bparams = new byte[params.length];
        for (int i = 0; i < params.length; i++) {
            bparams[i] = (byte) params[i];
        }
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
        ResponseAPDU response = send(0x00, 0x01, 0x00, 0x00);

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
        assertEquals("U2F_V2", new String(respWithoutStatus));
    }

    @Test
    public void testVersionInfo() {
        ResponseAPDU response = sendCTAP(0x04);

        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        byte[] data = response.getData();
        assertEquals(49, data.length);
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);
    }

    @Test
    public void testMakeCredential() {
        ResponseAPDU response = sendCTAP(
       0x01,                                      // authenticatorMakeCredential command
             0xa5,                                      // map(5)
   0x01,                                   // unsigned(1) - clientDataHash
   0x58, 0x20,                                // bytes(32)
      0x68, 0x71, 0x34, 0x96, 0x82, 0x22, 0xec, 0x17, 0x20, 0x2e, 0x42, 0x50, 0x5f, 0x8e, 0xd2, 0xb1,  // h’687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141'
      0x6a, 0xe2, 0x2f, 0x16, 0xbb, 0x05, 0xb8, 0x8c, 0x25, 0xdb, 0x9e, 0x60, 0x26, 0x45, 0xf1, 0x41,  //
   0x02,                                   // unsigned(2) - rp
   0xa2,                                   // map(2)
      0x62,                                // text(2)
         0x69, 0x64,                           // "id"
      0x6b,                                // text(11)
         0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,         // "example.com"
      0x64,                                // text(4)
         0x6e, 0x61, 0x6d, 0x65,                       // "name"
      0x64,                                // text(4)
         0x41, 0x63, 0x6d, 0x65,                       // "Acme"
   0x03,                                   // unsigned(3) - user
   0xa4,                                   // map(4)
      0x62,                                // text(2)
         0x69, 0x64,                           // "id"
      0x58, 0x20,                             // bytes(32)
         0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02,     // userid
         0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02,     // ...
         0x30, 0x82, 0x01, 0x93, 0x30, 0x82,                   // ...
      0x64,                                // text(4)
         0x69, 0x63, 0x6f, 0x6e,                       // "icon"
      0x78, 0x2b,                             // text(43)
         0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70, 0x69, 0x63, 0x73, 0x2e, 0x65, 0x78, // "https://pics.example.com/00/p/aBjjjpqPb.png"
         0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x30, 0x2f, 0x70, 0x2f, //
         0x61, 0x42, 0x6a, 0x6a, 0x6a, 0x70, 0x71, 0x50, 0x62, 0x2e, 0x70, 0x6e, 0x67,     //
      0x64,                                // text(4)
         0x6e, 0x61, 0x6d, 0x65,                       // "name"
      0x76,                                // text(22)
         0x6a, 0x6f, 0x68, 0x6e, 0x70, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x40, 0x65, 0x78, 0x61, 0x6d, // "johnpsmith@example.com"
         0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,                  // ...
      0x6b,                                 // text(11)
         0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65,          // "displayName"
      0x6d,                                 // text(13)
         0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x50, 0x2e, 0x20, 0x53, 0x6d, 0x69, 0x74, 0x68,      // "John P. Smith"
   0x04,                                    // unsigned(4) - pubKeyCredParams
   0x82,                                    // array(2)
      0xa2,                                 // map(2)
         0x63,                              // text(3)
            0x61, 0x6c, 0x67,                       // "alg"
         0x26,                              // -7 (ES256)
         0x64,                              // text(4)
            0x74, 0x79, 0x70, 0x65,                     // "type"
         0x6a,                              // text(10)
            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79,         // "public-key"
      0xa2,                                 // map(2)
         0x63,                              // text(3)
            0x61, 0x6c, 0x67,                       // "alg"
         0x39, 0x01, 0x00,                          // -257 (RS256)
         0x64,                              // text(4)
            0x74, 0x79, 0x70, 0x65,                     // "type"
         0x6a,                              // text(10)
            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79,         // "public-key"
   0x07,                                    // unsigned(7) - options
   0xa1,                                    // map(1)
      0x62,                                 // text(2)
         0x72, 0x6b,                            // "rk"
      0xf5                                 // primitive(21)
        );

        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        byte[] data = response.getData();
        assertNotEquals(0, data.length);
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);
    }

    @Test
    public void testGetAssertion_invalid() {
        ResponseAPDU response = sendCTAP(
                0x02,                                      // authenticatorGetAssertion command
                0xA4,                                      // map(4)
                0x01,                                   // unsigned(1)
                0x6b,                                   // text(11)
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,            // "example.com"
        0x02,                                   // unsigned(2)
        0x58, 0x20,                                // bytes(32)
        0x68, 0x71, 0x34, 0x96, 0x82, 0x22, 0xec, 0x17, 0x20, 0x2e, 0x42, 0x50, 0x5f, 0x8e, 0xd2, 0xb1,   // clientDataHash
        0x6a, 0xe2, 0x2f, 0x16, 0xbb, 0x05, 0xb8, 0x8c, 0x25, 0xdb, 0x9e, 0x60, 0x26, 0x45, 0xf1, 0x41,   // ...
        0x03,                                    // unsigned(3)
        0x82,                                    // array(2)
        0xa2,                                 // map(2)
        0x62,                              // text(2)
        0x69, 0x64,                         // "id"
        0x58, 0x40,                           // bytes(64)
        0xf2, 0x20, 0x06, 0xde, 0x4f, 0x90, 0x5a, 0xf6, 0x8a, 0x43, 0x94, 0x2f, 0x02,  // credential ID
        0x4f, 0x2a, 0x5e, 0xce, 0x60, 0x3d, 0x9c, 0x6d, 0x4b, 0x3d, 0xf8, 0xbe, 0x08,   // ...
        0xed, 0x01, 0xfc, 0x44, 0x26, 0x46, 0xd0, 0x34, 0x85, 0x8a, 0xc7, 0x5b, 0xed,   // ...
        0x3f, 0xd5, 0x80, 0xbf, 0x98, 0x08, 0xd9, 0x4f, 0xcb, 0xee, 0x82, 0xb9, 0xb2,   // ...
        0xef, 0x66, 0x77, 0xaf, 0x0a, 0xdc, 0xc3, 0x58, 0x52, 0xea, 0x6b, 0x9e,     // ...
        0x64,                              // text(4)
        0x74, 0x79, 0x70, 0x65,                     // "type"
        0x6a,                              // text(10)
        0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79,         // "public-key"
        0xa2,                                 // map(2)
        0x62,                              // text(2)
        0x69, 0x64,                         // "id"
        0x58, 0x32,                           // bytes(50)
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,   // credential ID
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,   // ...
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,   // ...
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,  // ...
        0x64,                              // text(4)
        0x74, 0x79, 0x70, 0x65,                     // "type"
        0x6a,                              // text(10)
        0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79,         // "public-key"
        0x05,                                    // unsigned(5)
        0xa1,                                    // map(1)
        0x62,                                 // text(2)
        0x75, 0x76,                            // "uv"
        0xf5                                 // true
        );

        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        byte[] data = response.getData();
        assertEquals(1, data.length);
        assertEquals(FIDOConstants.CTAP2_ERR_NO_CREDENTIALS, data[0]);
    }

    @Test
    public void testSystemDCryptEnroll() {
        ResponseAPDU r0 = sendCTAP(
        "01A5015820000000000000000000000000000000000000000000000000000000000000000002A262696475696F2E73797374656D642E63727970747365747570646E616D6570456E6372797074656420566F6C756D6503A3626964582435643930333061632D373133302D343963302D393431382D373863336364333362613165646E616D65782435643930333061632D373133302D343963302D393431382D3738633363643333626131656B646973706C61794E616D65781C2F686F6D652F627261756A61632F73632F70726574656E646469736B0481A263616C672664747970656A7075626C69632D6B657906A16B686D61632D736563726574F500"
        );
        assertEquals(ISO7816.SW_NO_ERROR, (short) r0.getSW());
        byte[] data = r0.getData();
        assertNotEquals(0, data.length);
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);

        ResponseAPDU r1 = sendCTAP(
        "06A20101020263"
        );
        assertEquals(ISO7816.SW_NO_ERROR, (short) r1.getSW());
        data = r1.getData();
        assertNotEquals(0, data.length);
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);

        ResponseAPDU r2 = sendCTAP(
            "02A50175696F2E73797374656D642E6372797074736574757002582000000000000000000000000000000000000000000000000000000000000000000381A26269645860CCF7130EE121D29ED8AEC5DEB3A6761F560DDF91C59F4ADF3749BD286C6B27A6B650193F72C858F1D27EA4DE60B85D018A773966E035327618610986B7392930A59D1E85ED99FC43BC34C0334A710DC7313565A6BD9354460D2F59B6C7CC4D7C64747970656A7075626C69632D6B657904A16B686D61632D736563726574A301A501020338182001215820320CCE78B2F352F133B0D658C58BF6F66EAE2C484346A254AAA9340407E9E378225820765D5EA42BED8A4E00F522AC6BEC3615FEE22F55729923BF81C7DEAB52A372EE0258206A1C6D9CCC4804A88C009DF802A4DB21C77B3220789D65DDCC47D50743A2761503507483E3D7D969D03505BAE3DE96CBF95F05A1627570F5B3"
        );
        assertEquals(ISO7816.SW_NO_ERROR, (short) r2.getSW());
        data = r2.getData();
        assertNotEquals(0, data.length);
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);
    }

    public void testHWSecurity() {
        // 80100000C701A6015820B38AD58E8EB3E54BABBB66218BA14C16B8057C5F26F9D0AC8002DFEF4677E49002A2626964766669646F2D6C6F67696E2E6578616D706C652E636F6D646E616D65781A4649444F2D4578616D706C652052656C79696E6720506172747903A36269645030B21834C24F1511CE4A9279E79B047F646E616D656874657374757365726B646973706C61794E616D656874657374757365720481A263616C672664747970656A7075626C69632D6B6579085024593DBB753EC6F81B005F0FA45D6BF9090100
        ResponseAPDU r0 = sendCTAP(
                "A6015820B38AD58E8EB3E54BABBB66218BA14C16B8057C5F26F9D0AC8002DFEF4677E49002A2626964766669646F2D6C6F67696E2E6578616D706C652E636F6D646E616D65781A4649444F2D4578616D706C652052656C79696E6720506172747903A36269645030B21834C24F1511CE4A9279E79B047F646E616D656874657374757365726B646973706C61794E616D656874657374757365720481A263616C672664747970656A7075626C69632D6B6579085024593DBB753EC6F81B005F0FA45D6BF90901"
        );
    }
}
