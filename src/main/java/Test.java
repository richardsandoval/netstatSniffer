import jpcap.packet.Packet;


/**
 * Created by rsandoval on 06/09/15.
 */
public class Test {

    public void handlePacket(Packet packet){
        System.out.println(packet);
    }

    public static void main(String... args){

        String[] devices = Jpcap.getDeviceList();

        for (int i = 0; i < devices.length; i++) {
            System.out.println(devices[i]);
        }

        String deviceName = devices[0];

        Jpcap jpcap = Jpcap.openDevice(deviceName, 1028, false, 1);
        jpcap.loopPacket(-1, new JpcapTip());

    }

}
