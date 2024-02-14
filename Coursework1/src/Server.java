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

                    //read hashed userID from client
                    String hashedUserID = din.readUTF();

                    //determine how many messages are stored for user
                    int numberOfMessages = getNumberOfMessagesForUserHash(hashedUserID);
                    System.out.println("Number of messages for user " + hashedUserID + ": " + numberOfMessages);
                    dout.writeInt(numberOfMessages);
                    dout.flush();

                    //ask client if they want to send a message
                    dout.writeUTF("Do you want to send a message? [y/n]");
                    dout.flush();


                    // If there are messages, send them
                    if (numberOfMessages > 0) {
                        List<String> messagesToSend = messagesForUserHash.get(hashedUserID);
                        for (String message : messagesToSend) {
                            dout.writeUTF(message); // Send each stored message to the client
                            dout.flush();
                        }
                        // Clear messages if you don't want to store them beyond this point
                        messagesForUserHash.put(hashedUserID, new ArrayList<>());
                    }


                    String clientResponse = din.readUTF();
                    if ("y".equalsIgnoreCase(clientResponse)) {
                       //read reciepient user id
                        String recipientUserID = din.readUTF();
                        System.out.println("Debug: Recipient's user ID received: " + recipientUserID);

                       //read lemgth of the message incoming
                        int messageLength = din.readInt();
                        System.out.println("Debug: Message length received: " + messageLength);
                        byte[] encryptedMessage = new byte[messageLength];
                        din.readFully(encryptedMessage);

                        // Decrypt and process the message
                        byte[] decryptedMessage = decrypt(encryptedMessage, serverPrivateKey);
                        String messageContent = new String(decryptedMessage);
                        System.out.println("Debug: Decrypted message: " + messageContent);

                        // Store the message for the recipient. Make sure recipientUserID is the hashed ID.
                        List<String> userMessages = messagesForUserHash.computeIfAbsent(recipientUserID, k -> new ArrayList<>());
                        userMessages.add(messageContent);

                        // Print details to server console
                        System.out.println("Message received from sender " + hashedUserID);
                        System.out.println("Recipient ID: " + recipientUserID);
                        System.out.println("Message: " + messageContent);

                        // Send an acknowledgment back to the client
                        dout.writeUTF("Message received.");
                        dout.flush();
                    } else {
                        // If the user response is not "y", you might want to handle "n" or any other response accordingly
                    }

                } catch(IOException e){
                    System.out.println("Error handling client: " + e.getMessage());
                } // Client socket is closed here due to try-with-resources
            }
        } catch (Exception e) {
            System.out.println("Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
