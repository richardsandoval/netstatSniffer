package packet;

import org.jnetpcap.packet.PcapPacket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Analyzer extends PacketAnalyzerRunnable {

    // byte array
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    // reference to the sniffer it is being used for
    private Sniffer sniffer;

    // list of interesting payloads
    private CopyOnWriteArrayList<String> relevantPayloads = new CopyOnWriteArrayList<String>();

    // list of decomposed packets
    private CopyOnWriteArrayList<CustomPacket> packetHeaders = new CopyOnWriteArrayList<CustomPacket>();

    // keyword list
    private final String[] keywords;

    //ctor for if you want a custom keywords list
    public Analyzer(Sniffer sniffer, String keywords[]) {
        this.sniffer = sniffer;
        this.keywords = keywords;
    }

    /**
     * Returns an array of relevant payloads as a String array
     *
     * @return String[] - the array of relevant payloads at the time
     */
    public String[] getRelevantPayloads() {
        return this.relevantPayloads.toArray(new String[this.relevantPayloads.size()]);
    }

    /**
     * Take the decomposed packetHeaders and returns the array of CustomPackets
     *
     * @return CustomPacket[]
     */
    public CustomPacket[] getPacketHeaders() {
        return this.packetHeaders.toArray(new CustomPacket[this.packetHeaders.size()]);
    }

    /**
     * Takes a byte array and returns the string version
     *
     * @param bytes
     */
    public static String toHex(byte[] bytes) {
        char[] c = new char[bytes.length * 2];
        int i = 0;
        for (byte b : bytes) {
            c[i++] = HEX[(b >> 4) & 0xf];
            c[i++] = HEX[b & 0xf];
        }
        return new String(c);
    }

    /**
     * Takes a string and removes all whitespace/newline characters
     *
     * @param in
     */
    public static String stripWhitespace(String in) {
        return in.replaceAll("\\s", "");
    }

    /**
     * Takes a hex representation of the payload and returns the content after the hex is converted to ascii chars NOTE: because of the way
     * regex works, this sometimes makes mistakes
     *
     * @param payload - the string contents of the payload
     */
    public static String getPayloadStr(String payload) {

        if (payload == null) {
            return ""; // return empty string to dodge nullptr excptions later
        }

        String pattern = "[a-f0-9][a-f0-9]\\s"; // the pattern for 1 byte
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(payload);

        ArrayList<String> hex_content = new ArrayList<String>();

        StringBuilder ret_val = new StringBuilder();

        while (m.find()) {
            // remove the whitespaces around the hex and add it to the arraylist
            hex_content.add(stripWhitespace(m.group()));
        }
        // loop through and convert each hex byte to a word
        for (String letter : hex_content) {
            try {
                int decimal = Integer.parseInt(letter, 16);
                ret_val.append((char) decimal);
            } catch (NumberFormatException e) {/* nop */
            } catch (Exception e) {/* nop */
            }
        }
        return ret_val.toString();
    }

    /**
     * Takes the payload string and removes any erroneous characters like multiple periods in a row multiple special characters.
     *
     * @param payload payload
     * @return String content without likely irrelevant character
     */
    public static String preprocess(String payload) {
        return null;
    }

    /**
     * Takes a packet and searches it's payload for the given array of keywords
     *
     * @param payload  The result of Payload.data().toString()
     * @param keywords [] - an array of keyterms to search for
     */
    public static String parsePayload(String payload, String keywords[]) {
        // get only the translated content of the payload
        String content = getPayloadStr(payload);
        // start by converting to lowercase
        content = content.toLowerCase();
        // boolean to check if at least one keyword was found
        boolean hit = false;
        // parse payload for keyword
        for (String keyword : keywords) {
            // regex stuff
            keyword = keyword.toLowerCase();
            if (content.contains(keyword)) {
                hit = true;
            }
        }
        if (hit) {
            return "========PAYLOAD========\n" + payload + "\n========END========\n";
        } else
            return null;
    }

    public static String parseHeader(String header, String keywords[]) {
        boolean hit = false;
        String content = new String(header);
        // set header to lowercase
        content = content.toLowerCase();
        // for each keyword
        for (String keyword : keywords) {
            if (content.contains(keyword)) {
                hit = true;
            }
        }
        if (hit) {
            return header;
        } else {
            return null;
        }
    }

    /**
     * Takes a packet, tears it up into its components, and stores it in an ArrayList<CustomPacket>.
     * <p>
     * Currently designed only to grab IPv4, TCP, UDP, and Payload headers Anything else is ignored
     *
     * @param packet
     */
    public void parse(PcapPacket packet) {
        CustomPacket cp = CustomPacket.parse(packet);

        if (cp == null)
            return;

        // search the ip headers
        if (cp.hasIp()) {
            String keywordMatch = null;
            keywordMatch = parseHeader(cp.getHeadIp().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }

        // search the tcp headers
        if (cp.hasTcp()) {
            String keywordMatch = null;
            keywordMatch = parseHeader(cp.getHeadTcp().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }

        // search the udp headers
        if (cp.hasUdp()) {
            String keywordMatch = null;
            keywordMatch = parseHeader(cp.getHeadUdp().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }

        // search the http header
        if (cp.hasHttp()) {
            String keywordMatch = null;
            keywordMatch = parseHeader(cp.getHeadHttp().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }


        // search the ethernet packet
        if (cp.hasEth()) {
            String keywordMatch = null;
            keywordMatch = parseHeader(cp.getHeadEth().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }

        // search the payloads
        if (cp.hasPayload()) {
            String keywordMatch = null;
            keywordMatch = parsePayload(cp.getPayload().toString(), this.keywords);
            if (keywordMatch != null) {
                this.relevantPayloads.add(keywordMatch);
//                this.window.registerRelevantPayload(cp, keywordMatch);
            }
        }

//        this.window.registerPacket(cp);
        this.packetHeaders.add(cp);
    }

    @Override
    protected String threadName() {
        try {
            return "Analyzer for " + CustomPacket.formatMACAddress(this.sniffer.device.getHardwareAddress());
        } catch (IOException e) {
            return "Analyzer";
        }
    }

    @Override
    protected void runLoop() {
        ArrayList<PcapPacket> packetsToProcess = this.sniffer.retreiveNewPackets();
        try {
            for (PcapPacket packet : packetsToProcess) {
                this.parse(packet);
            }
        } catch (Exception ex) {
            // ignore nullptrs
        }
    }
}