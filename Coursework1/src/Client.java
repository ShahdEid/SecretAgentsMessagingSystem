//import java.io.*;
//import java.net.*;
//import java.security.*;
//import java.util.Scanner;
//
//public class Client {
//
//    private static final String host = "localhost";
//    private static final int port = 5678;
//
//    public static void main(String[] args) throws UnknownHostException, IOException {
//        InetAddress address = InetAddress.getByName(host);
//        try (Socket socket = new Socket(address, port);
//             ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
//             ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
//             Scanner scanner = new Scanner(System.in)) {
//
//            // Send hashed user ID
//            output.writeObject(hashUserId("yourUserID"));
//
//            // Read the number of messages for the user
//            int messageCount = (int) input.readObject();
//            System.out.println("You have " + messageCount + " new message(s).");
//
//            // Receive and display messages
//            for (int i = 0; i < messageCount; i++) {
//                Message message = (Message) input.readObject();
//                displayMessage(message);
//            }
//
//            // Ask if the user wants to send a message
//            System.out.println("Do you want to send a message? [y/n]");
//            String answer = scanner.nextLine();
//
//            if ("y".equalsIgnoreCase(answer)) {
//                System.out.println("Enter the recipient userid:");
//                String recipientUserId = scanner.nextLine();
//                System.out.println("Enter your message:");
//                String text = scanner.nextLine();
//
//                Message messageToSend = createMessage(recipientUserId, text);
//                output.writeObject(messageToSend);
//            }
//        } catch (ClassNotFoundException e) {
//            System.err.println("Class not found: " + e.getMessage());
//        }
//    }
//
//    private static String hashUserId(String userId) {
//        // Implement user ID hashing logic
//        return null;
//    }
//
//    private static Message createMessage(String recipientUserId, String text) {
//        // Create and return a new message object
//        return null;
//    }
//
//    private static void displayMessage(Message message) {
//        // Display the message content
//    }
//
//    static class Message implements Serializable {
//        // Message class implementation
//    }
//}
