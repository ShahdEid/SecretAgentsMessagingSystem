import java.io.*;
import java.net.*;
//import java.security.*;
//import java.util.*;

public class Server {
    public static void main(String[] args) {
        try {
        ServerSocket ss= new ServerSocket(6666);
        Socket s = ss.accept(); //establishes a connection

            DataInputStream din = new DataInputStream(s.getInputStream());
            DataOutputStream dout = new DataOutputStream(s.getOutputStream());

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(System.in));

            String serverString, clientString;
            do {
                clientString = din.readUTF(); //read the input from the client
                System.out.println("client Says " + clientString); //print
                if (clientString.equals("stop")) {
                    break;
                } //stop if "stop"

                System.out.print("> "); //prompt user
                serverString = br.readLine(); //read input
                dout.writeUTF(serverString); //write it the outputstream
                dout.flush(); //send
            } while (!serverString.equals("stop")); //stop if "stop"

            din.close(); //close datainputstream
            dout.close(); //close dataoutputstream
            s.close(); //close the socket
            ss.close(); //close the server
            } catch (Exception e) {
            System.out.println(e);
        }

        }
    }

