import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) {
        try {
            Socket s = new Socket("localhost", 6666);

            DataInputStream din = new DataInputStream(s.getInputStream());
            DataOutputStream dout = new DataOutputStream(s.getOutputStream());

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            String serverString, clientString; // Fixed variable declaration
            do {
                System.out.print("> "); // Fixed System.out.print (It's System with 'S' not system)
                clientString = br.readLine(); // read their input
                dout.writeUTF(clientString); // write it to the output stream
                dout.flush(); // send
                if (clientString.equals("stop")) {
                    break; // stop if "stop"
                }

                serverString = din.readUTF(); // Fixed method call (din.readUTF() not dinreadUTF)
                System.out.println("Server says: " + serverString); // print it
            } while (!serverString.equals("stop")); // stop if "stop"

            din.close(); // close DataInputStream
            dout.close(); // close DataOutputStream
            s.close(); // Fixed method call (s.close() not s.clos())
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
