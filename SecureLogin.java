package securelogin;
import java.util.UUID;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;

/**
 *
 * @author gianl
 */

public class SecureLogin {

    public static void main(String[] args) {
        ServerLog sv = ServerLog.getServer();
        ClientLog u1 = new ClientLog();
        ClientLog u2 = new ClientLog();
        ClientLog u3 = new ClientLog();
        ClientLog u4 = new ClientLog();
        ClientLog u5 = new ClientLog();
        
        System.out.println("Inizio fase registrazione al server:");
        
        u1.signUpClient(sv, "utente1", "password1");
        u2.signUpClient(sv, "utente2", "password2");
        u2.signUpClient(sv, "utente2", "password1");
        u3.signUpClient(sv, "utente3", "password3");
        u4.signUpClient(sv, "utente4", "password4");
        u5.signUpClient(sv, "utente5", "password5");
        
        System.out.println();
        System.out.println("Inizio fase login al server:");
        
        u1.logInClient(sv, "utente1", "password2");
        u1.logInClient(sv, "utente1", "password1");
        u1.logInClient(sv, "utent1", "password1");
        u4.logInClient(sv, "utente4", "password5");
        u3.logInClient(sv, "utente3", "password3");
        
        sv.showMap();
    }
    
}

class DB {
    private final HashMap<String,String> database;
    
    public DB(){
        database= new HashMap<>();
    }
    
    public void insertDB(String k, String v){
        database.put(k, v);
    }
    
    public boolean isInDB(String k, String v){
        return database.containsKey(k) && database.containsValue(v) 
                && database.get(k).equals(v);
    }
    
    public void printMap() {
        Iterator it = database.entrySet().iterator();
        while (it.hasNext()) {
            HashMap.Entry pair = (HashMap.Entry)it.next();
            System.out.println(pair.getKey() + " : " + pair.getValue());
        }
    }
}

class ServerLog {
    private final DB serverDB;
    private final DB physicalDB;
    private final static ServerLog server = new ServerLog();
    
    public static ServerLog getServer(){
        return server;
    }
    
    private ServerLog() {
        serverDB = new DB();
        physicalDB = new DB();
    }
    
    public boolean signUpServer (ClientLog c, String username, String id, 
            String psw){
        if (serverDB.isInDB(username, id)){
            System.out.println("Registrazione già effettuata!");
            return false;
        }
        String stringUUID = UUID.randomUUID().toString();
        serverDB.insertDB(username, stringUUID);
        physicalDB.insertDB(produceDigest(stringUUID), produceDigest(psw));
        System.out.println("Registrazione effettuata con successo!");
        c.setID(stringUUID);
        return true;
    }
    
    public void logInServer (String username, String psw, String id){
        if (serverDB.isInDB(username, id) && 
                physicalDB.isInDB(produceDigest(id), produceDigest(psw))){
            System.out.println("Login sicuro effettuato!");
        }
        else{
            System.out.println("Credenziali errate!");
        }
    }
    
    private String produceDigest(String ms){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] H_md = md.digest(ms.getBytes());
            md.reset();
            String digest = hexEncoder(H_md);
            return digest;
        }
        catch (NoSuchAlgorithmException nsae) {return null;}
    }
    
    private String hexEncoder( byte[] input){
        StringBuffer result = new StringBuffer();
        char[] digits = {'0', '1', '2', '3', '4','5','6','7','8',
            '9','a','b','c','d','e','f'};
        for (int i = 0; i < input.length; ++i) {
            byte b = input[i];
            result.append( digits[ (b&0xf0) >> 4 ] );
            result.append( digits[ b&0x0f ] );
        }
        return result.toString();
    }
    
    public void showMap(){
        System.out.println();
        System.out.println("Mappa della relazione Username - ID");
        serverDB.printMap();
        System.out.println();
        System.out.println("Mappa della relazione ID - Password");
        physicalDB.printMap();
    }
}

class ClientLog {
    private String user_ID;
    
    public ClientLog(){
        user_ID = null;
    }
    
    public void setID(String id){
        user_ID = id;
    }
    
    public void signUpClient(ServerLog sl, String user, String psw){
        sl.signUpServer(this, user, user_ID ,psw);
    }
    
    public void logInClient (ServerLog sl, String user, String psw){
            sl.logInServer(user, psw, user_ID);
    }    
}