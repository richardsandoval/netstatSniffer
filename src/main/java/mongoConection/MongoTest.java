package mongoConection;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import static com.mongodb.client.model.Filters.*;

import java.util.List;

/**
 * Created by root on 18/10/15.
 */
public class MongoTest {


    public static void main(String... args){
        MongoClient mongoClient = new MongoClient("10.0.0.5", 27017);
//        List<String> dbs = mongoClient.getDatabaseNames();
//        dbs.forEach(System.out::println);

        MongoDatabase database = mongoClient.getDatabase("test");
//        System.out.println(get.runCommand(new BsonDocument()));
        MongoCollection<Document> collection = database.getCollection("accounts");

        System.out.print(collection.find(eq("user","jperez")).first().toJson());
        mongoClient.close();
    }

}
