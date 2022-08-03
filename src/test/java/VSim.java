import com.licel.jcardsim.remote.VSmartCard;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import us.q3q.fido2.FIDO2Applet;

public class VSim {

    static AID appletAID = AIDUtil.create("A0000006472F0001");

    public static void main(String[] args) throws Exception {
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.port", "35963");
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.delay", "1000");

        // This line requires a patched jcardsim...
        new VSmartCard("127.0.0.1", 35963, appletAID, FIDO2Applet.class);
    }

}
