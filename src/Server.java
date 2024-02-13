import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;



public class Server {

    //data structure to store msgs
    private static final HashMap<String, List<String>> messagesForUserHash = new HashMap<>();

   //NumberofmsgsForUserHashed method
    private static int getNumberOfMessagesForUserHash(String userHash) {
        List<String> messages = messagesForUserHash.get(userHash);
        return (messages != null) ? messages.size() : 0;
    }
    // Method to load the server's private key
    public static PrivateKey loadServerPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // Method to load a client's public key
    public static PublicKey loadClientPublicKey(String userID) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userID + ".pub"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // Method to decrypt a byte array message using a private key
    public static byte[] decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedMessage);
    }

    public static void main(String[] args) {
        System.out.println("Current working directory: " + System.getProperty("user.dir"));

        // Check if the correct number of arguments is passed
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started. Waiting for a connection...");

         //load server's prv key and use for all connections
            PrivateKey serverPrivateKey = loadServerPrivateKey("server.prv");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                try (DataInputStream din = new DataInputStream(clientSocket.getInputStream());
                     DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream())) {

                    System.out.println("Client Connected");
                    // Send a welcome message to the client
                    dout.writeUTF("Welcome to the Server!");
                    dout.flush();  // Ensure the message is sent immediately

                    //read the hashed UserID from client
                    String hashedUserID = din.readUTF();

                    // Determine how many messages are stored for the user
                    int numberOfMessages = getNumberOfMessagesForUserHash(hashedUserID);
                    System.out.println("Number of messages for user " + hashedUserID + ": " + numberOfMessages);
                    dout.writeInt(numberOfMessages); // Send the number of messages
                    dout.flush();





                    // Respond to the client with the number of messages
                    dout.writeInt(numberOfMessages);
                    dout.flush();


                    // Here, instead of just getting the number of messages, you would store the received message
//                    int length = din.readInt();  // Read message length
//                    if (length > 0) {
//                        byte[] message = new byte[length];
//                        din.readFully(message); // Read the message


                    if (numberOfMessages > 0) {
                        // Read the message length
                        int length = din.readInt();
                        byte[] message = new byte[length];
                        din.readFully(message); // Read the message
                        // Decrypt the message and perform further processing...
                        byte[] decryptedMessage = decrypt(message, serverPrivateKey);

                        // Store the decrypted message in your messagesForUserHash
                        List<String> userMessages = messagesForUserHash.computeIfAbsent(hashedUserID, k -> new ArrayList<>());
                        userMessages.add(new String(decryptedMessage)); // Assuming it's a string message
                    }



//                    // respond with number of msgs stored for this user
//                    int numberOfMessages = getNumberOfMessagesForUserHash(hashedUserID); // Calculate number of messages
//                    System.out.println("Number of messages for user " + hashedUserID + ": " + numberOfMessages);
//                    dout.writeInt(numberOfMessages); // Send the number of messages
//                    dout.flush();


                    // data structure to track messages for each user
                   // HashMap<String, List<String>> messagesForUserHash = new HashMap<>(); //commented out because it is redeclaring and clearing messages on each connection





//                    // The server is now prepared to read the incoming encrypted message from the client
//                    int length = din.readInt();  // Read message length
//                    if (length > 0) {
//                        byte[] message = new byte[length];
//                        din.readFully(message); // Read the message
//                        // Decrypt the message and perform further processing...
//                    }
                    // After processing the message, you can send back a response to the client if needed

                } catch (IOException e) {
                    System.out.println("Error handling client: " + e.getMessage());
                } finally {
                    clientSocket.close(); // Close the client socket after handling the client
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
