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
    private static final Map<String, List<String>> messagesForUserHash = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, List<String>> messagesForUser = new ConcurrentHashMap<>();
    private static PrivateKey serverPrivateKey;
    // A mapping of usernames to their hashed IDs
    private static final Map<String, String> usernameToHashedId = new HashMap<>();
    private static final Map<String, String> hashedIdToUsername = new HashMap<>();
    static {
        //populate the usernameToHashedId map
        usernameToHashedId.put("alice", HashingUtil.hashUsername("alice"));
        usernameToHashedId.put("bob", HashingUtil.hashUsername("bob"));
        // Populate reverse map
        for (Map.Entry<String, String> entry : usernameToHashedId.entrySet()) {
            hashedIdToUsername.put(entry.getValue(), entry.getKey());
        }
    }
    public static String getUsernameFromHashedId(String hashedId) {
        for (Map.Entry<String, String> entry : usernameToHashedId.entrySet()) {
            if (entry.getValue().equals(hashedId)) {
                return entry.getKey(); // username corresponding to the hashed ID
            }
        }
        return null; //the username is not found
    }
    private static int getNumberOfMessagesForUserHash(String userHash) {
        List<String> messages = messagesForUserHash.get(userHash);
        return (messages != null) ? messages.size() : 0;
    }
    public static PrivateKey loadServerPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey loadClientPublicKeyByUsername(String username) throws Exception {
        String publicKeyFilename = username + ".pub"; // Construct the filename with the username
        System.out.println("Loading public key from file: " + publicKeyFilename);
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static void storeMessage(String recipientHashedId, String message) {
        System.out.println("storing message for recipientHashedID: " + recipientHashedId + "Message: " + message);
        messagesForUserHash.computeIfAbsent(recipientHashedId, k -> new ArrayList<>()).add(message);
    }
    public static List<String> retrieveMessages(String userHashedId) {
        return messagesForUserHash.getOrDefault(userHashedId, new ArrayList<>());
    }

    public static void clearMessages(String userHashedId) {
        messagesForUserHash.remove(userHashedId);
    }

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

                    System.out.println("login from user " + hashedUserID);
                    dout.writeInt(messagesForUser.size());
                    dout.flush();

                    for (String message : messagesForUser) {
                        dout.writeUTF(message);
                        dout.flush();
                    }

                    clearMessages(hashedUserID);

                    dout.writeUTF("Do you want to send a message? [y/n]");
                    dout.flush();

                    String clientResponse = din.readUTF();

                    if ("y".equalsIgnoreCase(clientResponse)) {
                        String recipientUsername = din.readUTF();
                        String recipientHashedID = usernameToHashedId.get(recipientUsername);
                        String actualRecipientUsername = getUsernameFromHashedId(recipientHashedID);
                        PublicKey recipientPublicKey = loadClientPublicKeyByUsername(recipientUsername);
                        // Get the actual username of the sender
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


                            byte[] messageBytes = messageContent.getBytes();
                            byte[] encryptedForRecipient = encrypt(messageContent.getBytes(), recipientPublicKey); // Re-encrypt the message with the recipient's public key

                            String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedForRecipient);

                            storeMessage(recipientHashedID, Base64.getEncoder().encodeToString(encryptedForRecipient)); // Store the re-encrypted message instead of plaintext
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


}