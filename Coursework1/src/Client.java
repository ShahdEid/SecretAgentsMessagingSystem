import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.nio.file.Paths;
import java.util.Base64;

public class Client {
    public static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static byte[] encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);  //encrption Mode
        return cipher.doFinal(message.getBytes());
    }

    public static byte[] decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedMessage);
    }

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

        if (args.length != 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

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

        try (
                Socket socket = new Socket(host, port);
                DataInputStream din = new DataInputStream(socket.getInputStream());
                DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in))
        ) {
            PublicKey serverPublicKey = loadPublicKey("server.pub");
            PrivateKey clientPrivateKey = loadPrivateKey(userid + ".prv");

            // Read the welcome message from the server
            String welcomeMessage = din.readUTF();
            System.out.println(welcomeMessage);

            String hashedUserID = HashingUtil.hashUsername(userid);
            dout.writeUTF(hashedUserID);
            dout.flush();

            int messageCount = din.readInt();
            System.out.println("Number of messages stored for you: " + messageCount);

            for (int i = 0; i < messageCount; i++) {
                String base64EncodedEncryptedMessage = din.readUTF();
                byte[] encryptedMessageBytes = Base64.getDecoder().decode(base64EncodedEncryptedMessage);

                Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                decryptCipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
                byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
                String decryptedMessage = new String(decryptedMessageBytes);

                System.out.println("Message " + (i + 1) + ": " + decryptedMessage);
            }

            boolean continueSending = true; // Flag to control the loop
            boolean firstMessage = true;
            while (continueSending) {
                // Determine the prompt based on whether it's the first message or not
                String prompt = firstMessage ? "Do you want to send a message? [y/n]" : "Do you want to send another message? [y/n]";
                System.out.println(prompt); // Show prompt to the user
                String userInput = br.readLine(); // Read user input

                // Send the response to the server (if your server expects this every time)
                dout.writeUTF(userInput);
                dout.flush();

                if ("y".equalsIgnoreCase(userInput)) {
                    // It's no longer the first message
                    firstMessage = false;

                    // User wants to send a message
                    System.out.print("Enter your message: ");
                    String clientMessage = br.readLine(); // Read the message from the user

                    System.out.print("Enter User ID of recipient: ");
                    String recipientUserID = br.readLine(); // Read recipient user ID from the user

                    // Encrypt the message with the server's public key and send it along with the recipient's UserID
                    byte[] encryptedMessage = encrypt(clientMessage, serverPublicKey);
                    dout.writeUTF(recipientUserID);
                    dout.writeInt(encryptedMessage.length);
                    dout.write(encryptedMessage);
                    dout.flush();
                    System.out.println("Message sent.");
                } else if ("n".equalsIgnoreCase(userInput)) {
                    continueSending = false; // User does not want to send more messages
                } else {
                    System.out.println("Invalid input. Please enter 'y' to send a message or 'n' to quit.");
                }
            }
            br.close();
            dout.close();
            din.close();
            socket.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
