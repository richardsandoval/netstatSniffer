package main;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import packet.CustomPacket;
import packet.Sniffer;

import java.text.ParseException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static com.mongodb.client.model.Filters.eq;

/**
 * Created by root on 18/10/15.
 */
public class Main {

    static List<PcapIf> devices = new ArrayList<>();
    static List<Sniffer> sniffers = new ArrayList<>();
    static CopyOnWriteArrayList<CustomPacket> packets = new CopyOnWriteArrayList<>();
    static MongoClient client;
    static MongoDatabase database;
    public static MongoCollection<Document> DATA_SNIFFER;
    public static Document data;
    static CopyOnWriteArrayList<Document> sniffer;

    public static void main(String... args) throws ParseException {

        client = new MongoClient(args[0], 27017);
        database = client.getDatabase("test");
        DATA_SNIFFER = database.getCollection("datas");
        sniffers = new ArrayList<>();
        sniffer = new CopyOnWriteArrayList<>();

        data = new Document("start", new BasicDBObject("date", new Date()));
        DATA_SNIFFER.insertOne(data);
        data = DATA_SNIFFER.find(eq("start", data.get("start"))).first();

        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(devices, errbuf);
        if (r == Pcap.NOT_OK || devices.isEmpty()) {
            System.err.println(devices.isEmpty());
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }
//        select();
        run();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            data.append("ends", new BasicDBObject("date", new Date()));
            data.append("networkData", sniffer.stream().map(e -> e.get("_id")).collect(Collectors.toList()));
//            data.append("networkData", sniffer);
            DATA_SNIFFER.replaceOne(eq("_id", data.get("_id")), data);
            client.close();
        }));

    }

    private static void select() {
        for (PcapIf device : devices)
            System.out.println(String.format(" device : %s - %s ", device.getName(), device.getDescription()));
    }

    private static void run() {

        ExecutorService executor = Executors.newCachedThreadPool();
        devices.stream().filter(device -> !device.getDescription().contains("w")).forEach(device -> {
            Sniffer sniffer = new Sniffer(device);
            sniffers.add(sniffer);
            executor.execute(sniffer);
        });
    }

    public static void registerPacket(CustomPacket packet) {
        packets.add(packet);
        updatePacketCount();
        addMongoDocument(packet);
    }

    private synchronized static void addMongoDocument(CustomPacket packet) {
        MongoCollection<Document> networkData = database.getCollection("sniffers");
        Document document = new Document();
        document.append("_id", new ObjectId());
//        document.append("dataId", data.get("_id"));
        document.append("timestamp", new BasicDBObject("date", new Date()));
        document.append("isTCP", !packet.hasUdp());
//        try {
//            if (packet.hasEth()) {
//                document.append("sMAC", packet.getMacSrc());
//                document.append("dMAC", packet.getMacDest());
//            }
//            if (packet.hasIp()) {
//
//                document.append("sIP", packet.getIpSrc());
//                document.append("dIP: ", packet.getIpDest());
//            }
//            if (packet.hasUdp()) {
//                document.append("sUDP", packet.getUdpSrc());
//                document.append("dUDP", packet.getUdpDest());
//            }
//            if (packet.hasTcp()) {
//
//                document.append("sTCP", packet.getTcpSrc());
//                document.append("dTCP", packet.getTcpDest());
//                document.append("protocol", packet.getHeadTcp().source());
//
//                //append flags
//                document.append("flags", Arrays.asList(packet.getTcpFlags()));
//
//            }
//            if (packet.hasHttp()) {
//                document.append("httpHeader", packet.getHeadHttp().toString());
//            }
//            if (packet.hasPayload()) {
//                document.append("length", packet.getPayload().dataLength());
//                document.append("payload", packet.getPayload().toString());
//            } else {
//                document.append("length", 0);
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
        networkData.insertOne(document);
        sniffer.add(document);
    }

    private synchronized static void updatePacketCount() {
        System.out.println("Packet Found: " + packets.size());
    }

}
