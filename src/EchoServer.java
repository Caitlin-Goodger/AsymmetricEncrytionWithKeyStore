import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyStore cybr372KeyStore;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port, String serverPass) throws  KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException{
        serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());
        byte[] data = new byte[256];
        byte[] insignatureBytes = new byte[256];
        int numBytes;
        while ((numBytes = in.read(data)) != -1) {
            // decrypt data
            in.read(insignatureBytes);

            //Read the server's private key and the client's public key from the key store
            Key key = cybr372KeyStore.getKey("server", serverPass.toCharArray());
            PrivateKey serverPri = null;

            if(key instanceof PrivateKey) {
                serverPri = (PrivateKey) key;
            }

            PublicKey clientPub =  cybr372KeyStore.getCertificate("client").getPublicKey();



            Cipher cipher = Cipher.getInstance(encrpytion);
            cipher.init(Cipher.DECRYPT_MODE, serverPri);

            byte[] decryptedBytes = cipher.doFinal(data);
            String decOut = new String(decryptedBytes, "UTF-8");
            System.out.println("Server received cleartext "+decOut);

            //Authenticate the signature using the client's public key
            Signature insig = Signature.getInstance(signing);
            insig.initVerify(clientPub);
            insig.update(decryptedBytes);
            boolean signatureValid = insig.verify(insignatureBytes);

            if(signatureValid) {
                System.out.println("Signature Valid");
            } else {
                System.out.println("Signature Invalid");
                throw new SignatureException();
            }

            // encrypt response (this is just the decrypted data re-encrypted)


            cipher = Cipher.getInstance(encrpytion);
            cipher.init(Cipher.ENCRYPT_MODE, clientPub);

            byte[] cipherBytes = cipher.doFinal(decryptedBytes);
            Base64.Encoder en = Base64.getEncoder();
            System.out.println("Server sending ciphertext "+ new String(en.encode(cipherBytes)));

            //Sign the message with the server's private key
            Signature sig = Signature.getInstance(signing);
            sig.initSign(serverPri);
            sig.update(decryptedBytes);
            byte[] signatureBytes = sig.sign();
            //Send the encrypted message and the signature to the client.
            out.write(cipherBytes);
            out.write(signatureBytes);
            out.flush();
        }
        stop();


    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Initialise the key store
     * @param location = key store location
     * @param keyPass = key store password
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void keyStoring(String location, String keyPass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        File keyStoreLocation = null;
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if(location != null) {
            keyStoreLocation = new File(location);
            keyStore.load(new FileInputStream(keyStoreLocation),keyPass.toCharArray());
        }

        System.out.println("Stored keys at " + keyStoreLocation);

        cybr372KeyStore = keyStore;




    }

    /**
     * Arguments in order keyStorageLocation, keyStorage password, server password
     * @param args
     */
    public static void main(String[] args) throws CertificateException, KeyStoreException, UnrecoverableKeyException {
        EchoServer server = new EchoServer();
        try {
            if(args.length != 3) {
                System.out.println("Please enter the correct parameters. keyStorageLocation, keyStorage password, server password");
                return;
            }
            String location = args[0];
            String keyPassword = args[1];
            String serverPass = args[2];
            server.keyStoring(location,keyPassword);
            System.out.println("Waiting to complete Exchange");
            server.start(4444,serverPass);
        } catch (NoSuchAlgorithmException e){
        System.out.println("That algorithm can't be found. Please try again");
        } catch (NoSuchPaddingException e) {
        System.out.println("There isn't enough padding for this encryption. Please try again");
        } catch (InvalidKeyException e) {
        System.out.println("That isn't a valid key. Please try again and enter a valid key");
        } catch (IllegalBlockSizeException e) {
        System.out.println("There is not enough space for this cipher. Please try again");
        } catch (BadPaddingException e) {
        System.out.println("There isn't enough padding for this encryption. Please try again.");
        } catch (SignatureException e) {
        System.out.println("The signature doesn't match. This message may not be from the right person");
        } catch (IOException e) {
        System.out.println("There is with the key store. Please check that the location provided is correct and try again\"");
        } catch (IllegalArgumentException e) {
        System.out.println("A Key should be longer than 2 bytes. Please try again with a valid key");
        }
    }

}



