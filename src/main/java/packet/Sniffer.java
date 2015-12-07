package packet;

import main.Daemon;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.LinkedBlockingQueue;

public class Sniffer extends PacketAnalyzerRunnable {
    final int snaplen = 64 * 1024; // Capture all packets, no truncation
    final int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
    final int timeout = 10 * 1000; // 10 seconds in millis


    public final PcapIf device;
    private Pcap pcap;
    private StringBuilder errbuf = new StringBuilder();
    private LinkedBlockingQueue<PcapPacket> queue = new LinkedBlockingQueue<PcapPacket>();
     
    private LinkedBlockingQueue<PcapPacket> newPackets = new LinkedBlockingQueue<PcapPacket>();
    private ArrayList<PcapPacket> readPackets = new ArrayList<PcapPacket>();

    public Sniffer( PcapIf device) {
        this.device = device;
    }
    
    @Override
    protected String threadName() {
        try {
            return "Sniffer for " + CustomPacket.formatMACAddress(this.device.getHardwareAddress());
        } catch (IOException e) {
            return "Sniffer";
        }
    }

    @Override
    protected void init() {
        this.pcap = Pcap.openLive(this.device.getName(), this.snaplen, this.flags, this.timeout, this.errbuf);

        if (this.pcap == null) {
            System.err.printf("Error while opening device for capture: " + this.errbuf.toString());
            return;
        }
    }

    @Override
    protected void runLoop() {
        try {
            PcapPacketHandler<LinkedBlockingQueue<PcapPacket>> handler = new PcapPacketHandler<LinkedBlockingQueue<PcapPacket>>() {
                @Override
                public void nextPacket(PcapPacket packet, LinkedBlockingQueue<PcapPacket> queue) {
                    PcapPacket permanent = new PcapPacket(packet);
                    queue.offer(permanent);
                }
            };

            if (this.pcap.loop(1, handler, this.queue) == 0) {
                while (!this.queue.isEmpty()) {
                    PcapPacket packet = new PcapPacket(this.queue.poll());

                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        return;
                    }

                    this.recordNewPacket(packet);
                }
            }
        } catch (RuntimeException ignore) {
        }
    }

    public synchronized void recordNewPacket(PcapPacket packet) {
        PcapPacket copy = new PcapPacket(packet);
        
//        this.window.registerPacket(CustomPacket.parse(copy));
        Daemon.registerPacket(CustomPacket.parse(copy));
        this.newPackets.add(copy);
    }

    public synchronized ArrayList<PcapPacket> retreiveNewPackets() {
        ArrayList<PcapPacket> result = new ArrayList<>();
        while (!this.newPackets.isEmpty()) {
            PcapPacket copy = new PcapPacket(this.newPackets.poll());
            this.readPackets.add(copy);
            result.add(copy);
        }
        return result;
    }
}
