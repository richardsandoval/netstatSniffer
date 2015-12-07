package packet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;
import java.util.List;

public class SendPackets {
    public static void main(String[] args) {
        List<PcapIf> allDevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        StringBuilder errBuf = new StringBuilder(); // For any error msgs


        //* First get a list of devices on this system

        int r = Pcap.findAllDevs(allDevs, errBuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errBuf.toString());
            return;
        }
        PcapIf device = allDevs.get(0); // We know we have atleast 1 device

        int snapLen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snapLen, flags, timeout, errBuf);


        //create packet
        JPacket packet =
                new JMemoryPacket(JProtocol.ETHERNET_ID,
                        " 001801bf 6adc0025 4bb7afec 08004500 "
                                + " 0041a983 40004006 d69ac0a8 00342f8c "
                                + " ca30c3ef 008f2e80 11f52ea8 4b578018 "
                                + " ffffa6ea 00000101 080a152e ef03002a "
                                + " 2c943538 322e3430 204e4f4f 500d0a");


        Ip4 ip = packet.getHeader(new Ip4());
        Ip6 ip6 = packet.getHeader(new Ip6());
        Tcp tcp = packet.getHeader(new Tcp());


                tcp.destination(80);

        tcp.flags(0); //set all flags to zero

        //form Christmas flags
        tcp.flags_FIN(true);
        tcp.flags_PSH(true);
        tcp.flags_URG(true);

        //set mac

        //set ip

        //set payload


        ip.checksum(ip.calculateChecksum());
        tcp.checksum(tcp.calculateChecksum());
        packet.scan(Ethernet.ID);

        //send packets infinitely
        while (true) {
            if (pcap.sendPacket(packet) != Pcap.OK) {
                System.err.println(pcap.getErr());
            }
        }

        /********************************************************
         * Lastly we close
         ********************************************************/
        //pcap.close();  //for now we don't close
    }
}  