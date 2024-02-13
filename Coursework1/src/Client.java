import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.nio.file.Paths;


public class Client {
    // Method to load the public key of the server
    public static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }


    // Method to load the private key of the client
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    // Method to encrypt a string using a public key
    public static byte[] encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);  //encrption Mode
        return cipher.doFinal(message.getBytes());
    }
    //Method to hash userID with MD5 algo and gfh2024 before hashing
    public static String hashUserID(String userID) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(("gfhk2024:" + userID).getBytes());
            byte[] digest = md.digest();
            return toHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    public static void main(String[] args) {


        System.out.println("Current working directory: " + System.getProperty("user.dir"));


        // Check if the correct number of arguments is passed
        if (args.length != 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            return;
        }




        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2]; // "alice" or "bob"
        //System.out.println("TRYING TO LOAD PRV KEY FOR USERID: " + userid);
        //String privateKeyFilename = userid + " .prv";
        //System.out.println("PRV KEY FILENMAE: " + privateKeyFilename);


        // Check if the client's private key file exists
        File clientPrivateKeyFile = new File(userid + ".prv");
        if (!clientPrivateKeyFile.exists()) {
            System.err.println("Error: Private key file not found: " + clientPrivateKeyFile.getAbsolutePath());
            return;
        }




        // Check if the server's public key file exists
        File serverPublicKeyFile = new File("server.pub");
        if (!serverPublicKeyFile.exists()) {
            System.err.println("Error: Server public key file not found: " + serverPublicKeyFile.getAbsolutePath());
            return;
        }


        try {
            Socket socket = new Socket(host, port);
            DataInputStream din = new DataInputStream(socket.getInputStream());
            DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));


            // Load the public key of the server
            PublicKey serverPublicKey = loadPublicKey("server.pub");
            PrivateKey clientPrivateKey = loadPrivateKey(userid + ".prv");


            // Read the welcome message from the server
            String welcomeMessage = din.readUTF();
            System.out.println(welcomeMessage);


            //send hashed userID after establishing a connection to the server
            String hashedUserID = hashUserID(userid);
            //send hashed userid to server
            dout.writeUTF(hashedUserID);
            dout.flush();


            // Read the number of messages the server has for this client
            int messageCount = din.readInt();
            System.out.println("Number of messages stored for you: " + messageCount);


            // If there are messages, read and decrypt them
            for (int i = 0; i < messageCount; i++) {
                // The server would need to send the length of the encrypted message followed by the encrypted message itself
                int messageLength = din.readInt();
                byte[] encryptedMessage = new byte[messageLength];
                din.readFully(encryptedMessage);
                // Decrypt the message here using the client's private key
                // ...
            }




            // Get user input for the message
            System.out.print("> ");
            String clientMessage = br.readLine(); // Read the message from the user


            // Encrypt the message with the server's public key
            byte[] encryptedMessage = encrypt(clientMessage, serverPublicKey);


            // Send the encrypted message length and the encrypted message itself
            dout.writeInt(encryptedMessage.length);
            dout.write(encryptedMessage);
            dout.flush();


            // Close all resources after sending one message
            br.close();
            dout.close();
            din.close();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
