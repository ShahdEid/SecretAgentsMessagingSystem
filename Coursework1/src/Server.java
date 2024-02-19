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
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.*;
import java.security.*;
import java.util.*;
import java.security.MessageDigest;



public class Server {

    // data structure to store messages
   // private static final HashMap<String, List<String>> messagesForUserHash = new HashMap<>();

    private static final Map<String, List<String>> messagesForUserHash = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, List<String>> messagesForUser = new ConcurrentHashMap<>();
    private static PrivateKey serverPrivateKey;
    // A mapping of usernames to their hashed IDs
    private static final Map<String, String> usernameToHashedId = new HashMap<>();

    private static final Map<String, String> hashedIdToUsername = new HashMap<>();
//    static {
//        usernameToHashedId.put("alice", "hashed_id_of_alice");
//        usernameToHashedId.put("bob", "hashed_id_of_bob");
//        // Log the mappings for verification
//        usernameToHashedId.forEach((username, hashedId) -> System.out.println("Mapping: " + username + " -> " + hashedId));
//    }
static {
    // At server startup, populate the usernameToHashedId map
    usernameToHashedId.put("alice", HashingUtil.hashUsername("alice"));
    usernameToHashedId.put("bob", HashingUtil.hashUsername("bob"));
    // Populate reverse map
    for (Map.Entry<String, String> entry : usernameToHashedId.entrySet()) {
        hashedIdToUsername.put(entry.getValue(), entry.getKey());
    }
}
    // Method to get username from hashed ID
    public static String getUsernameFromHashedId(String hashedId) {
        for (Map.Entry<String, String> entry : usernameToHashedId.entrySet()) {
            if (entry.getValue().equals(hashedId)) {
                return entry.getKey(); // This is the username corresponding to the hashed ID
            }
        }
        return null; // Or handle the case where the username is not found
    }
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
    // Method to load a client's public key by username
    public static PublicKey loadClientPublicKeyByUsername(String username) throws Exception {
        String publicKeyFilename = username + ".pub"; // Construct the filename with the username
        System.out.println("Loading public key from file: " + publicKeyFilename); // Debug print statement

        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // Method to store a message for a hashed ID
    public static void storeMessage(String recipientHashedId, String message) {
        System.out.println("storing message for recipientHashedID: " + recipientHashedId + "Message: " + message);
        messagesForUserHash.computeIfAbsent(recipientHashedId, k -> new ArrayList<>()).add(message);
    }

    // Method to retrieve messages for a hashed ID
    public static List<String> retrieveMessages(String userHashedId) {
        return messagesForUserHash.getOrDefault(userHashedId, new ArrayList<>());
    }

    // Method to clear messages for a hashed ID
    public static void clearMessages(String userHashedId) {
        messagesForUserHash.remove(userHashedId);
    }

    // Method to decrypt a byte array message using a private key
    public static byte[] decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedMessage);
    }
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }



    public static void main(String[] args) {
        System.out.println("Current working directory: " + System.getProperty("user.dir"));

        // Check if the correct number of arguments is passed
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        PrivateKey serverPrivateKey = null;

        try {
            serverPrivateKey = loadServerPrivateKey("server.prv");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started. Waiting for a connection...");

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                     DataInputStream din = new DataInputStream(clientSocket.getInputStream());
                     DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream())) {

                    System.out.println("Client Connected");

                    dout.writeUTF("Welcome to the Server!");
                    dout.flush();

                    String hashedUserID = din.readUTF();
                    List<String> messagesForUser = retrieveMessages(hashedUserID);
                    // Print the login message with the hashed user ID
                    System.out.println("login from user " + hashedUserID);
                    dout.writeInt(messagesForUser.size());
                    dout.flush();

                    for (String message : messagesForUser) {
                        dout.writeUTF(message);
                        dout.flush();
                    }

                    // Optionally clear messages after sending
                     clearMessages(hashedUserID);

                    dout.writeUTF("Do you want to send a message? [y/n]");
                    dout.flush();

                    String clientResponse = din.readUTF();

                    if ("y".equalsIgnoreCase(clientResponse)) {
                        String recipientUsername = din.readUTF();
                        String recipientHashedID = usernameToHashedId.get(recipientUsername);
                        String actualRecipientUsername = getUsernameFromHashedId(recipientHashedID);
                        PublicKey recipientPublicKey = loadClientPublicKeyByUsername(recipientUsername);
                       // Get the actual username of the sender for display purposes
                        String senderUsername = getUsernameFromHashedId(hashedUserID);

                        if (recipientHashedID != null) {
                            int messageLength = din.readInt();
                            byte[] encryptedMessage = new byte[messageLength];
                            din.readFully(encryptedMessage);

                            byte[] decryptedMessage = decrypt(encryptedMessage, serverPrivateKey);
                            String messageContent = new String(decryptedMessage);

                            // print the required info
                            System.out.println("incoming message from " + senderUsername);
                            System.out.println("recipient: " + recipientUsername);
                            System.out.println("message: " + messageContent);

                            //Assume `recipientPublicKey` is the public key of the recipient
                           // PublicKey recipientPublicKey = loadClientPublicKeyByUsername(recipientHashedID );
                            // Convert the message content to bytes
                            byte[] messageBytes = messageContent.getBytes();
                            // Re-encrypt the message with the recipient's public key
                            byte[] encryptedForRecipient = encrypt(messageContent.getBytes(), recipientPublicKey);

                            // Assuming you need to convert encrypted bytes to a storable format (like base64) before storing
                            String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedForRecipient);

                            // Store the re-encrypted message instead of plaintext

                            storeMessage(recipientHashedID, Base64.getEncoder().encodeToString(encryptedForRecipient));
                            dout.writeUTF("Message received and stored for " + recipientUsername);
                            dout.flush();
                        } else {
                            System.out.println("Recipient username not recognized: " + recipientUsername);
                            dout.writeUTF("Recipient username not recognized.");
                            dout.flush();
                        }
                    } else {
                        System.out.println("Client does not want to send a message");
                    }

                } catch (IOException e) {
                    System.out.println("Error handling client: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.out.println("Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

//            while (true) {
//                try ( Socket clientSocket = serverSocket.accept();
//                     DataInputStream din = new DataInputStream(clientSocket.getInputStream());
//                     DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream())) {
//
//                    System.out.println("Client Connected");
//                    dout.writeUTF("Welcome to the Server!");
//                   dout.flush();
//
//                    //read hashed userID from client
//                    String hashedUserID = din.readUTF(); // user's hashed id received from the client
//                    // Retrieve the stored messages for this user
//                    List<String> messagesForUser = retrieveMessages(hashedUserID);
//
//                    // Send the number of messages to the client so they know how many to expect
//                    dout.writeInt(messagesForUser.size());
//                    dout.flush();
//                    for (String message : messagesForUser) {
//                        dout.writeUTF(message);
//                        dout.flush();
//                    }
////                    // Only attempt to send messages if they exist
////                    if (messagesForUser != null && !messagesForUser.isEmpty()) {
////                        for (String message : messagesForUser) {
////                            dout.writeUTF(message); // Send each stored message to the client
////                            dout.flush(); // Ensure each message is sent immediately
////                        }
////                    }
//                    // Loop through the messages and send each one to the client
////                    for (String message : messagesForUser) {
////                        dout.writeUTF(message);
////                      //  dout.flush();
////                    }
//                    dout.writeUTF("Do you want to send a message? [y/n]");
//                    dout.flush();
//                    String clientResponse = din.readUTF(); // Wait for user response
//
//                    //determine how many messages are stored for user
//                    int numberOfMessages = getNumberOfMessagesForUserHash(hashedUserID);
//                    System.out.println("Number of messages for user " + hashedUserID + ": " + numberOfMessages);
//                    dout.writeInt(numberOfMessages);
//                    dout.flush();
//
////
////                    // If there are messages, send them
////                    if (numberOfMessages > 0) {
////                        List<String> messagesToSend = messagesForUserHash.get(hashedUserID);
////                        for (String message : messagesToSend) {
////                            dout.writeUTF(message); // Send each stored message to the client
////                            dout.flush();
////                        }
////                       //clearMessages(hashedUserID);
////                    }
//                    //ask client if they want to send a message
////                    dout.writeUTF("Do you want to send a message? [y/n]");
////                    dout.flush();
//
//                    // Send the number of messages to the client so they know how many to expect
//                   // dout.writeInt(messagesForUser.size());
//                    dout.flush(); // Ensure data is sent to the client
//
//                    // If there are messages, send them
////                    if (numberOfMessages > 0) {
////                        List<String> messagesToSend = messagesForUserHash.get(hashedUserID);
////                        for (String message : messagesToSend) {
////                            dout.writeUTF(message); // Send each stored message to the client
////                            dout.flush();
////                        }
//////                        // Clear messages if you don't want to store them beyond this point
//////                        messagesForUserHash.remove(hashedUserID, new ArrayList<>());
////                    }
//                    //dout.writeUTF("Do you want to send a message? [y/n]");
//                  //  dout.flush();
//
//                   // String clientResponse = din.readUTF();
//                    if ("y".equalsIgnoreCase(clientResponse)) {
//                        // Read recipient's username and get the hashed ID from the map
//                        String recipientUsername = din.readUTF();
//                        String recipientHashedID = usernameToHashedId.get(recipientUsername);
//
//                        if (recipientHashedID != null) {
//                            // Read the length and content of the message
//                            int messageLength = din.readInt();
//                            System.out.println("Debug: Message length received: " + messageLength);
//                            byte[] encryptedMessage = new byte[messageLength];
//                            din.readFully(encryptedMessage);
//
//                            // Decrypt and process the message
//                            byte[] decryptedMessage = decrypt(encryptedMessage, serverPrivateKey);
//                            String messageContent = new String(decryptedMessage);
//                            System.out.println("Received message to store: " + messageContent + " for recipientHashedID: " + recipientHashedID);
//
//                            // Store the message for the recipient
//                            storeMessage(recipientHashedID, messageContent);
//
//                            // Acknowledge the receipt of the message
//                            dout.writeUTF("Message received and stored for " + recipientUsername);
//                            dout.flush();
//                        } else {
//                            // If the username is not recognized, inform the client
//                            System.out.println("Recipient username not recognized: " + recipientUsername);
//                            dout.writeUTF("Recipient username not recognized.");
//                            dout.flush();
//                        }
//                    } else {
//                        System.out.println("Client does not want to send a message");
//                    }
//
//
//                } catch(IOException e){
//                    System.out.println("Error handling client: " + e.getMessage());
//                    e.printStackTrace();
//                } // Client socket is closed here due to try-with-resources
//            }
//        } catch (Exception e) {
//            System.out.println("Server exception: " + e.getMessage());
//            e.printStackTrace();
//        }
//    }
}