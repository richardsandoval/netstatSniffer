package main;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.apache.commons.io.IOUtils;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.json.JSONObject;
import packet.CustomPacket;
import packet.Sniffer;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.mongodb.client.model.Filters.eq;
import static java.lang.System.*;

/**
 * Created by root on 01/11/15.
 */
public class Daemon {

    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";


    static List<PcapIf> devices = new ArrayList<>();
    static List<Sniffer> sniffs = new ArrayList<>();
    static CopyOnWriteArrayList<CustomPacket> packets = new CopyOnWriteArrayList<>();
    static MongoClient client;
    static MongoDatabase database;
    public MongoCollection<Document> organizations;
    public MongoCollection<Document> staffs;
    public MongoCollection<Document> accounts;
    public MongoCollection<Document> datas;
    public static MongoCollection<Document> sniffers;
    //    CopyOnWriteArrayList<Document> sniffer;
    Document account = null;
    Document staff = null;
    Document organization = null;
    static Document data = new Document();

    public void run() {

        JSONObject jsonObject = null;
//        try {
//            jsonObject = new JSONObject(IOUtils.toString(getClass().getClassLoader().getResourceAsStream("config.json")));
            jsonObject = new JSONObject("{\n" +
                    "    \"name\": \"Netstats Analyzer\",\n" +
                    "    \"version\": 1.0,\n" +
                    "    \"configure\": {\n" +
                    "        \"general\": {\n" +
                    "            \"sandbox\": true\n" +
                    "        },\n" +
                    "        \"mongo\": {\n" +
                    "            \"ip\": \"netstatspucmm.com\",\n" +
                    "            \"port\": 27017,\n" +
                    "            \"database\": \"netstats\",\n" +
                    "            \"collection\": {\n" +
                    "                \"principal\": \"organizations\",\n" +
                    "                \"personal\": \"staffs\",\n" +
                    "                \"account\": \"accounts\",\n" +
                    "                \"dataSniffer\": \"datas\",\n" +
                    "                \"networkData\": \"sniffers\"\n" +
                    "            }\n" +
                    "        }\n" +
                    "    }\n" +
                    "}");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

        configureMongo(jsonObject, false);
        login();
    }

    private void login() {
        Scanner scanner = new Scanner(in);
        try {
            Runtime.getRuntime().exec("clear");
        } catch (IOException e) {
            e.printStackTrace();
        }
        out.println("NETSTATS");
        while (true) {
            out.println("Login");
            out.print("User: ");
            String user = scanner.nextLine();
//            if (user.equalsIgnoreCase("local"))
//                break;
            out.print("Password: ");
            String pass = scanner.nextLine();
            account = accounts.find(new Document("user", user).append("pwr", pass)).first();
            if (account == null) {
                out.println(ANSI_GREEN + "Usuario/Contrasena Incorrecta" + ANSI_RESET);
                continue;
            }
            staff = staffs.find(new Document("_id", account.getObjectId("staffId"))).first();
            organization = organizations.find(new Document("_id", staff.getObjectId("organizationId"))).first();
            if (account != null) {

                break;
            }
        }
        logged(scanner);
    }

    private void logged(Scanner scanner) {
        if (staff != null)
            out.println(ANSI_BLUE + String.format("Bienvenido %s %s", staff.getString("name"), staff.getString("lastname")) + ANSI_RESET);
        int i = 0;
        while (i < 1 || i > 4) {
            out.println(ANSI_YELLOW + "ACCIONES\n1. Iniciar Sniffer con subida local\n2. Iniciar Sniffer con subida remota\n3. Subir analisís a la Base de datos remota\n4. Salir");
            try {
                out.print("Selección: ");
                i = Integer.valueOf(scanner.nextLine());
            } catch (Exception e) {
                i = -1;
            }
        }
        switch (i) {
            case 1:
                start();

                break;
            case 3:
                break;
            case 4:
                break;
            default:
                break;
        }
    }

    private void start() {
        data = new Document("start", new BasicDBObject("date", new Date()))
                .append("accountId", account.getObjectId("_id"));
//        sniffer = new CopyOnWriteArrayList<>();
        datas.insertOne(data);
        data = datas.find(eq("start", data.get("start"))).first();

        configureDevices();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            data.append("ends", new BasicDBObject("date", new Date()));
            datas.replaceOne(eq("_id", data.get("_id")), data);
        }));
    }

    private void configureDevices() {
        ExecutorService executor = Executors.newCachedThreadPool();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(devices, errbuf);
        if (r == Pcap.NOT_OK || devices.isEmpty()) {
            err.println(devices.isEmpty());
            err.printf("Can't read list of devices, error is %s", errbuf.toString());
        }

        out.println("Seleccione Dispositivos : ");
        devices.forEach(d ->
                out.println(String.format("%s. device : %s - %s ", devices.indexOf(d), d.getName(), d.getDescription()))
        );

        devices.forEach(device -> {

            Sniffer sniffer = new Sniffer(device);
            sniffs.add(sniffer);
            executor.execute(sniffer);

        });
    }

    private void configureMongo(JSONObject jsonObject, Boolean local) {
        JSONObject mongoConfig = ((JSONObject) ((JSONObject) jsonObject.get("configure")).get("mongo"));
        JSONObject collections = (JSONObject) mongoConfig.get("collection");
        client = new MongoClient(
                local ? "localhost" : mongoConfig.getString("ip"),
                mongoConfig.getInt("port")
        );
        database = client.getDatabase(mongoConfig.getString("database"));
        organizations = database.getCollection(collections.getString("principal"));
        staffs = database.getCollection(collections.getString("personal"));
        accounts = database.getCollection(collections.getString("account"));
        datas = database.getCollection(collections.getString("dataSniffer"));
        sniffers = database.getCollection(collections.getString("networkData"));

    }

    public static void registerPacket(CustomPacket packet) {
        packets.add(packet);
        updatePacketCount();
        addMongoDocument(packet);
    }

    private static void addMongoDocument(CustomPacket packet) {
        Document analysis = new Document();
        analysis.append("_id", new ObjectId())
                .append("dataId", data.getObjectId("_id"))
                .append("timestamp", new BasicDBObject("date", new Date()));
        try {
            if (packet.hasEth()) {
                analysis.append("sMAC", packet.getMacSrc());
                analysis.append("dMAC", packet.getMacDest());
            }
            if (packet.hasIp()) {
                analysis.append("length", packet.getHeadIp().getLength());
                analysis.append("sIP", packet.getIpSrc());
                analysis.append("dIP", packet.getIpDest());
            }
            if (packet.hasUdp()) {
                analysis.append("sUDP", packet.getUdpSrc());
                analysis.append("dUDP", packet.getUdpDest());
                analysis.append("isTCP", !packet.hasUdp());
            }
            if (packet.hasTcp()) {

                analysis.append("sTCP", packet.getTcpSrc());
                analysis.append("dTCP", packet.getTcpDest());

                if (packet.getTcpSrc() == 27017 || packet.getTcpDest() == 27017)
                    return;

                analysis.append("protocol", packet.getHeadTcp().source());
                analysis.append("isTCP", packet.hasTcp());

                //append flags
                analysis.append("flags", Arrays.asList(packet.getTcpFlags()));

            }
            if (packet.hasHttp()) {
                analysis.append("httpHeader", packet.getHeadHttp().toString());
            }
            if (packet.hasPayload()) {
                analysis.append("payload_length", packet.getPayload().dataLength());
                analysis.append("payload", packet.getPayload().toString());
            } else {
                analysis.append("payload_length", 0);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        sniffers.insertOne(analysis);

    }

    private synchronized static void updatePacketCount() {
        out.println(ANSI_CYAN + "Packet Found: " + packets.size() + ANSI_RESET);
    }

    public static void main(String... args) {
        Daemon daemon = new Daemon();
        daemon.run();
    }

}
