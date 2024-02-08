//import java.io.*;
//import java.net.*;
//import java.security.*;
//import java.util.*;
//
//public class Server {
//
//    private static final int port = 5678;
//    private static Map<String, List<Message>> messageStore = new HashMap<>();
//
//    public static void main(String[] args) {
//        try (ServerSocket serverSocket = new ServerSocket(port)) {
//            System.out.println("Server is listening on port " + port);
//
//            while (true) {
//                try (Socket socket = serverSocket.accept();
//                     ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
//                     ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {
//
//                    // Receive hashed user ID
//                    String hashedUserId = (String) input.readObject();
//
//                    // Send number of messages for the user
//                    List<Message> userMessages = messageStore.getOrDefault(hashedUserId, new ArrayList<>());
//                    output.writeObject(userMessages.size());
//
//                    // Send messages to the client
//                    for (Message message : userMessages) {
//                        output.writeObject(message);
//                    }
//                    messageStore.remove(hashedUserId); // Clear sent messages
//
//                    // Receive and process a message from the client
//                    Message incomingMessage = (Message) input.readObject();
//                    processIncomingMessage(incomingMessage);
//                } catch (ClassNotFoundException e) {
//                    System.err.println("Class not found: " + e.getMessage());
//                } catch (IOException e) {
//                    System.err.println("I/O error: " + e.getMessage());
//                }
//            }
//        } catch (IOException e) {
//            System.err.println("Server exception: " + e.getMessage());
//        }
//    }
//
//    private static void processIncomingMessage(Message incomingMessage) {
//        // Process and store the incoming message
//        // You will need to implement the logic based on your assignment requirements
//    }
//
//    static class Message implements Serializable {
//        // Message class implementation
//    }
//}
