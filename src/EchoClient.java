import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;
import sun.security.x509.X500Name;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyStore cybr372KeyStore;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port){
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg, String clientPass) throws  KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        System.out.println("Client sending cleartext "+msg);
        byte[] data = msg.getBytes("UTF-8");
        Cipher cipher = Cipher.getInstance(encrpytion);

        //Get the Server public key from the keystore and the client's private key
        PublicKey serverPub =cybr372KeyStore.getCertificate("server").getPublicKey();
        PrivateKey clientPrivate = null;

        Key clientkey = cybr372KeyStore.getKey("client", clientPass.toCharArray());
        if(clientkey instanceof PrivateKey) {
            clientPrivate = (PrivateKey) clientkey;
        }

        cipher.init(Cipher.ENCRYPT_MODE, serverPub);
        byte[] cipherBytes = cipher.doFinal(data);

        //Sign the message using the client's private key
        Signature sig = Signature.getInstance(signing);
        sig.initSign(clientPrivate);
        sig.update(data);
        byte[] signatureBytes = sig.sign();
        Base64.Encoder en = Base64.getEncoder();
        System.out.println("Client sending ciphertext "+ new String(en.encode(cipherBytes)));
        //Send the encrypted message and signature to the server
        out.write(cipherBytes);
        out.write(signatureBytes);
        out.flush();
        byte[] incoming = new byte[256];
        byte [] insignatureBytes = new byte[256];
        in.read(incoming);
        in.read(insignatureBytes);
        //Decrypt using the client's private key
        cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.DECRYPT_MODE, clientPrivate);
        byte[] decryptedBytes = cipher.doFinal(incoming);
        String decOut = new String(decryptedBytes, "UTF-8");
        System.out.println("Client received cleartext "+decOut);

        //Authenticate the signature using the server's public key
        Signature insig = Signature.getInstance(signing);
        insig.initVerify(serverPub);
        insig.update(decryptedBytes);
        boolean signatureValid = insig.verify(insignatureBytes);
        if(signatureValid) {
            System.out.println("Signature Valid");
        } else {
            System.out.println("Signature Invalid");
            throw new SignatureException();
        }
        return decOut;
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    /**
     * Initialise the key store
     * @param location - the location of the key store
     * @param password - the password for the key store
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void keyStoring(String location, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        File keyStoreLocation = null;
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if(location != null) {
            keyStoreLocation = new File(location);
            keyStore.load(new FileInputStream(keyStoreLocation),password.toCharArray());
        }
        System.out.println("Stored keys at " + keyStoreLocation);
        cybr372KeyStore = keyStore;


    }


    /**
     * Arguments in order keyStorageLocation, keyStorage password, client password
     * @param args
     */
    public static void main(String[] args) {
        EchoClient client = new EchoClient();

        if(args.length != 3) {
            System.out.println("Please enter the correct parameters. keyStorageLocation, keyStorage password, client password");
            return;
        }
        String location = args[0];
        String keyPassword = args[1];
        String clientpass = args[2];

        try {
            client.keyStoring(location,keyPassword);


            System.out.println("Keys exchanged");

            client.startConnection("127.0.0.1", 4444);
            client.sendMessage("12345678", clientpass);
            client.sendMessage("ABCDEFGH", clientpass);
            client.sendMessage("87654321", clientpass);
            client.sendMessage("HGFEDCBA", clientpass);

            client.stopConnection();
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
        } catch (NullPointerException e) {
            System.out.println("Please start the Server before the Client. Please give the public key to the server firts");
        } catch (KeyStoreException e) {
            System.out.println("That isn't a valid key. Please try again and enter a valid key.");
        }catch (CertificateException e) {
            System.out.println("There is an issue with the Key Store. Please try again and enter a valid key");
        } catch (UnrecoverableKeyException e) {
            System.out.println("That key isn't valid. Please try again");
        }
    }
}
