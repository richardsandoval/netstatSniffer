package packet;

import org.bson.Document;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.ArrayList;

public class CustomPacket {
    private Ip4 headIp;
    private Ip6 headIp6;
    private Tcp headTcp;
    private Udp headUdp;
    private Http headHttp;
    private Payload payload;
    private Ethernet headEth;

    public CustomPacket() {
        this.headIp = null;
        this.headIp6 = null;
        this.headTcp = null;
        this.headUdp = null;
        this.headHttp = null;
        this.headEth = null;
        this.payload = null;
    }

    public static String byteToIp(byte[] in) {
        String hexAddr = Analyzer.toHex(in);
        String ipAddr = "";
        for (int i = 0; i < hexAddr.length() - 1; i += 2) {
            try {
                int decimal = Integer.parseInt(hexAddr.substring(i, i + 2), 16);
                ipAddr += decimal + ".";
            } catch (Exception e) {/* nop */
            }
        }

        return ipAddr.substring(0, ipAddr.length() - 1); // return without that last '.'
    }

    public static String formatMACAddress(byte[] macAddress) {
        StringBuilder sb = new StringBuilder();

        String prefix = "";

        try {
            for (byte b : macAddress) {
                sb.append(prefix);
                prefix = "-";
                sb.append(String.format("%02X", b));
            }
        } catch (Exception e) {

        }

        return sb.toString();
    }

    public String getIpSrc() {
        if (!this.hasIp())
            return null;
        return byteToIp(this.headIp.source());
    }

    public String getIpDest() {
        if (!this.hasIp())
            return null;
        return byteToIp(this.headIp.destination());
    }

    public boolean isIPFragment() {
        if (!this.hasIp())
            return false;
        return this.headIp.isFragment();
    }

    public int getUdpSrc() {
        if (!this.hasUdp())
            return -1;
        return this.headUdp.source();
    }

    public int getUdpDest() {
        if (!this.hasUdp())
            return -1;
        return this.headUdp.destination();
    }

    public int getTcpSrc() {
        if (!this.hasTcp())
            return -1;
        return this.headTcp.source();
    }

    public int getTcpDest() {
        if (!this.hasTcp())
            return -1;
        return this.headTcp.destination();
    }


    public Ip4 getHeadIp() {
        return this.headIp;
    }

    public Tcp getHeadTcp() {
        return this.headTcp;
    }

    public Udp getHeadUdp() {
        return this.headUdp;
    }

    public Http getHeadHttp() {
        return this.headHttp;
    }

    public Ethernet getHeadEth() {
        return this.headEth;
    }

    public Payload getPayload() {
        return this.payload;
    }

    /**
     * Flags (8 bits) (aka Control bits) - contains 8 1-bit flags<br/>
     * <ul>
     * <li>CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the
     * ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).</li>
     * <li>ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the TCP peer is ECN capable. If the SYN flag is clear, that a
     * packet with Congestion Experienced flag in IP header set is received during normal transmission (added to header by RFC 3168).</li>
     * <li>URG (1 bit) - indicates that the Urgent pointer field is significant.</li>
     * <li>ACK (1 bit) - indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client
     * should have this flag set.</li>
     * <li>PSH (1 bit) - Push function. Asks to push the buffered data to the receiving application.</li>
     * <li>RST (1 bit) - Reset the connection.</li>
     * <li>SYN (1 bit) - Synchronize sequence numbers. Only the first packet sent from each end should have this flag set. Some other flags
     * change meaning based on this flag, and some are only valid for when it is set, and others when it is clear.</li>
     * <li>FIN (1 bit) - No more data from sender.
     * </ul>
     */
    public String[] getTcpFlags() {
        if (!this.hasTcp())
            return null;
        ArrayList<String> flags = new ArrayList<String>();
        if (this.headTcp.flags_ACK())
            flags.add("ACK");
        if (this.headTcp.flags_CWR())
            flags.add("CWR");
        if (this.headTcp.flags_ECE())
            flags.add("ECE");
        if (this.headTcp.flags_FIN())
            flags.add("FIN");
        if (this.headTcp.flags_PSH())
            flags.add("PSH");
        if (this.headTcp.flags_RST())
            flags.add("RST");
        if (this.headTcp.flags_SYN())
            flags.add("SYN");
        if (this.headTcp.flags_URG())
            flags.add("URG");
        return flags.toArray(new String[flags.size()]);
    }

    public long getTcpAck() {
        if (!this.hasTcp())
            return -1;
        return this.headTcp.ack();
    }

    public int getTcpWindowSize() {
        if (!this.hasTcp())
            return -1;
        return this.headTcp.window();
    }

    public long getTcpSeq() {
        if (!this.hasTcp())
            return -1;
        return this.headTcp.seq();
    }

    public String getMacSrc() {
        if (!this.hasEth())
            return null;
        return formatMACAddress(this.headEth.source());
    }

    public String getMacDest() {
        if (!this.hasEth())
            return null;
        return formatMACAddress(this.headEth.destination());
    }

    public boolean hasIp() {
        return this.headIp != null;
    }

    public  boolean hasIpV6(){
        return this.headIp6 != null;
    }

    public boolean hasTcp() {
        return this.headTcp != null;
    }

    public boolean hasUdp() {
        return this.headUdp != null;
    }

    public boolean hasHttp() {
        return this.headHttp != null;
    }

    public boolean hasEth() {
        return this.headEth != null;
    }

    public boolean hasPayload() {
        return this.payload != null;
    }


    public String forwardingString() {
        StringBuilder result = new StringBuilder();
        try {
            if (this.hasIp()) {
                result.append("SRC IP: ").append(this.getIpSrc()).append("\n");
                result.append("DEST IP: ").append(this.getIpDest());
            } else if (this.hasEth()) {
                result.append("SRC MAC: ").append(this.getMacSrc()).append("\n");
                result.append("DEST MAC: ").append(this.getMacDest());
            } else if (this.hasUdp()) {
                result.append("SRC UDP: ").append(this.getUdpSrc()).append("\n");
                result.append("DEST UDP: ").append(this.getUdpDest());
            } else if (this.hasTcp()) {
                result.append("SRC TCP: ").append(this.getTcpSrc()).append("\n");
                result.append("DEST TCP: ").append(this.getTcpSrc()).append("\n");


                //append flags
                result.append("Flags: ");
                String flags[] = this.getTcpFlags();
                for (String flag : flags) {
                    result.append(flag).append(" ");
                }
                result.append("\n");

                result.append("Sequence #: ").append(this.getTcpSeq()).append("\n");
                result.append("ACK #: ").append(this.getTcpAck());
            } else if (this.hasHttp()) {

            } else {
                result.append("Error parsing forwarding information.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result.toString();
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        try {
            if (this.hasEth()) {
                result.append("SRC MAC: " + this.getMacSrc() + "\n");
                result.append("DEST MAC: " + this.getMacDest() + "\n");
            }
            if (this.hasIp()) {
                result.append("SRC IP: " + this.getIpSrc() + "\n");
                result.append("DEST IP: " + this.getIpDest() + "\n");
            }
            if (this.hasUdp()) {
                result.append("SRC UDP: " + this.getUdpSrc() + "\n");
                result.append("DEST UDP: " + this.getUdpDest() + "\n");
            }
            if (this.hasTcp()) {
                result.append("SRC TCP: " + this.getTcpSrc() + "\n");
                result.append("DEST TCP: " + this.getTcpDest() + "\n");

                //append flags
                result.append("Flags: ");
                String flags[] = this.getTcpFlags();
                for (String flag : flags) {
                    result.append(flag + " ");
                }
                result.append("\n");

                result.append("Sequence #: " + this.getTcpSeq() + "\n");
                result.append("ACK #: " + this.getTcpAck() + "\n");
                result.append("Receiving Window Size: " + this.getTcpWindowSize());
            }
            if (this.hasHttp()) {
                result.append(this.headHttp.toString());
            }
            if (this.hasPayload()) {
                result.append(this.payload.toString());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result.toString();
    }

    public static CustomPacket parse(PcapPacket packet) {
        Ethernet eth = new Ethernet();
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Http http = new Http();
        Html html = new Html();
        Payload payload = new Payload();
        CustomPacket cp = new CustomPacket();

        if (packet == null)
            return null;

        // save the ethernet packet
        if (packet.hasHeader(eth))
            cp.headEth = eth;

        // save the ip headers
        if (packet.hasHeader(ip))
            cp.headIp = ip;

        // save the tcp headers
        if (packet.hasHeader(tcp))
            cp.headTcp = tcp;

        // save the udp headers
        if (packet.hasHeader(udp))
            cp.headUdp = udp;

        // save the http header
        if (packet.hasHeader(http))
            cp.headHttp = http;

        // save the html header
        if (packet.hasHeader(html))
            cp.headHttp = http;

        // save the payloads
        if (packet.hasHeader(payload))
            cp.payload = payload;

        return cp;
    }
}