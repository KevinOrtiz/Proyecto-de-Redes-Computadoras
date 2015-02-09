/*
 *
 */
package chat1;

/**
 *
 * @author pcn
 *//* ChatClient.java */

/* ChatClient.java */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Encoder;

public class ChatClient {

    private static int port = 50500; /* port to connect to */

    private static String host = "192.168.10.121"; /* host to connect to (server's IP)*/

    private static BufferedReader stdIn;
    private static String nick;

    /**
     * Read in a nickname from stdin and attempt to authenticate with the server
     * by sending a NICK command to @out. If the response from @in is not equal
     * to "OK" go bacl and read a nickname again
     */
    private static String getNick(BufferedReader in,
            PrintWriter out) throws IOException {

        System.out.print("Enter your nick: ");
        String msg = stdIn.readLine();
        out.println("NICK " + msg);
        String serverResponse = in.readLine();
        if ("SERVER: OK".equals(serverResponse)) {
            return msg;
        }
        System.out.println(serverResponse);
        return getNick(in, out);
    }

    public static void main(String[] args) throws IOException {
        Socket server = null;
        try {
            server = new Socket(host, port);
        } catch (UnknownHostException e) {
            System.err.println(e);
            System.exit(1);
        }
        stdIn = new BufferedReader(new InputStreamReader(System.in));
        /* obtain an output stream to the server... */
        PrintWriter out = new PrintWriter(server.getOutputStream(), true);
        /* ... and an input stream */
        BufferedReader in = new BufferedReader(new InputStreamReader(
                server.getInputStream()));
        nick = getNick(in, out);
        /* create a thread to asyncronously read messages from the server */
        ServerConn sc = new ServerConn(server);
        Thread t = new Thread(sc);
        t.start();
        String msg;
        byte[] iv = null;
        String strDataToEncrypt = new String();
        String strCipherText = new String();
        String strDecryptedText = new String();
        SecretKey secretKey = null;
        try {
            /**
             * Step 1. Generate an AES key using KeyGenerator Initialize the
             * keysize to 128 bits (16 bytes)
             *
             */
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();

            /**
             * Step 2. Generate an Initialization Vector (IV) a. Use
             * SecureRandom to generate random bits The size of the IV matches
             * the blocksize of the cipher (128 bits for AES) b. Construct the
             * appropriate IvParameterSpec object for the data to pass to
             * Cipher's init() method
             */
            final int AES_KEYLENGTH = 128;	// change this as desired for the security level you want
            iv = new byte[AES_KEYLENGTH / 8];	// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
            SecureRandom prng = new SecureRandom();
            prng.nextBytes(iv);

            /**
             * Step 3. Create a Cipher by specifying the following parameters a.
             * Algorithm name - here it is AES b. Mode - here it is CBC mode c.
             * Padding - e.g. PKCS7 or PKCS5
             */
        } catch (NoSuchAlgorithmException noSuchAlgo) {
            System.out.println(" No Such Algorithm exists " + noSuchAlgo);
        }
        /* loop reading messages from stdin and sending them to the server */
        while ((msg = stdIn.readLine()) != null) {
            try {
                Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!

                /**
                 * Step 4. Initialize the Cipher for Encryption
                 */
                aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey,
                        new IvParameterSpec(iv));

                /*Encryption*/
                /**
                 *
                 *
                 * Step 5. Encrypt the Data a. Declare / Initialize the Data.
                 * Here the data is of type String b. Convert the Input Text to
                 * Bytes c. Encrypt the bytes using doFinal method
                 */
                strDataToEncrypt = msg;
                byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
                byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
                // b64 is done differently on Android
                strCipherText = new BASE64Encoder().encode(byteCipherText);
			//System.out.println("Cipher Text generated using AES is "
                //		+ strCipherText);

                /**
                 * Step 6. Decrypt the Data a. Initialize a new instance of
                 * Cipher for Decryption (normally don't reuse the same object)
                 * Be sure to obtain the same IV bytes for CBC mode. b. Decrypt
                 * the cipher bytes using doFinal method
                 */
                Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!				

                aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey,
                        new IvParameterSpec(iv));
                byte[] byteDecryptedText = aesCipherForDecryption
                        .doFinal(byteCipherText);
                strDecryptedText = new String(byteDecryptedText);
			//System.out
                //		.println(" Decrypted Text message is " + strDecryptedText);
            } catch (NoSuchAlgorithmException noSuchAlgo) {
                System.out.println(" No Such Algorithm exists " + noSuchAlgo);
            } catch (NoSuchPaddingException noSuchPad) {
                System.out.println(" No Such Padding exists " + noSuchPad);
            } catch (InvalidKeyException invalidKey) {
                System.out.println(" Invalid Key " + invalidKey);
            } catch (BadPaddingException badPadding) {
                System.out.println(" Bad Padding " + badPadding);
            } catch (IllegalBlockSizeException illegalBlockSize) {
                System.out.println(" Illegal Block Size " + illegalBlockSize);
            } catch (InvalidAlgorithmParameterException invalidParam) {
                System.out.println(" Invalid Parameter " + invalidParam);
            }
            out.println(strCipherText);
        }
    }
}

class ServerConn implements Runnable {

    private BufferedReader in = null;

    public ServerConn(Socket server) throws IOException {
        /* obtain an input stream from the server */
        in = new BufferedReader(new InputStreamReader(
                server.getInputStream()));
    }

    public void run() {
        String msg;

        try {
            /* loop reading messages from the server and show them
             * on stdout */
            while ((msg = in.readLine()) != null) {

                System.out.println(msg);
            }
        } catch (IOException e) {
            System.err.println(e);
        }
    }
}
