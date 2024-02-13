import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EncryptionDecryptionTest {
    public static void main(String[] args) {
        try {
            // Load the keys just like in your client and server
            PublicKey publicKey = Client.loadPublicKey("server.pub");
            PrivateKey privateKey = Server.loadServerPrivateKey("server.prv");

            // Encrypt a test message
            String message = "Test message";
            byte[] encryptedMessage = Client.encrypt(message, publicKey);

            // Decrypt the message
           // String decryptedMessage = new String(Server.decrypt(encryptedMessage, privateKey));
            String decryptedMessage = new String(decrypt(encryptedMessage, privateKey));
            // Check if the original message and decrypted message match
            System.out.println("Original message: " + message);
            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    // Method to decrypt a byte array message using a private key
    public static byte[] decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedMessage);
    }

}

