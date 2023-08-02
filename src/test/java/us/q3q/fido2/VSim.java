package us.q3q.fido2;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.remote.VSmartCard;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import java.lang.reflect.Field;

/**
 * Launches jcardsim with VSmartCard connectivity
 */
public class VSim {

    static final AID appletAID = AIDUtil.create("A0000006472F0001");
    static final int PORT = 35963;

    public static Simulator startBackgroundSimulator() throws Exception {
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.port", "" + PORT);
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.delay", "1000");

        VSmartCard sc = new VSmartCard("127.0.0.1", PORT);

        // The JCardSim VSmartCard class doesn't natively support loading applets at startup...
        // ... and it also doesn't provide access to the Simulator class necessary to do that!
        // To avoid needing to patch VCardSim, we'll violate Java member visibility rules
        // and reach directly into the class to install our applet.
        Field f = sc.getClass().getDeclaredField("sim");
        f.setAccessible(true);
        return (Simulator) f.get(sc);
    }

    public static synchronized void installApplet(Simulator sim, byte[] params) {
        if (params.length > 255) {
            throw new IllegalArgumentException("Install parameters too long!");
        }
        sim.installApplet(appletAID, FIDO2Applet.class, params, (short) 0, (byte) params.length);
        sim.selectApplet(appletAID);
    }

    public static Simulator startForegroundSimulator() {
        return new Simulator();
    }

    public static synchronized byte[] transmitCommand(Simulator sim, byte[] command) {
        return sim.transmitCommand(command);
    }

    public static synchronized void softReset(Simulator sim) {
        sim.reset();
        sim.selectApplet(appletAID);
    }

    public static void main(String[] args) throws Exception {
        Simulator sim = startBackgroundSimulator();

        installApplet(sim, new byte[0]);
    }

}
