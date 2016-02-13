import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        KeyPair keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        } catch (Exception e) {
            System.err.println("RSA keypair generation failed: " + e.toString());
        }


        Gson gson = new GsonBuilder().create();

        String clearText;

        String serverHostname = new String("localhost");


        Socket cSocket = new Socket(serverHostname, 7777);
        PrintWriter pw = new PrintWriter(cSocket.getOutputStream(), true);
        BufferedReader br = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));

        String jsonPubPacket = br.readLine();

        System.out.println("SERVER PUBLIC PACKET RECEIVED: " + jsonPubPacket);
        Packet pubPacket = gson.fromJson(jsonPubPacket,Packet.class);
        Packet privPacket = new Packet();

        if(pubPacket.PublicOrPrivate.equals("public")){
            System.out.println("Public Packet: TRUE");
        }else{
            System.out.println("Public Packet: FALSE");
            System.exit(1);
        }

        if((new HexBinaryAdapter()).marshal(md.digest(pubPacket.publicKey.getBytes())).equals(pubPacket.sig)){
            System.out.println("Public Packet Integrity: VERIFIED: " + pubPacket.sig);
        }else{
            System.out.println("Public Packet Integrity: FAILED");
            System.out.println("PACKET DAMAGE (UN-LIKELEY) OR INTERCEPTION CHANGE IN TRANSIT: ABORT ABORT ABORT");
            System.exit(1);
        }

        final Cipher cipher = Cipher.getInstance("RSA");

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(pubPacket.publicKey)));

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        privPacket.PublicOrPrivate = "private";



        while(true) {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            Scanner in = new Scanner(System.in);
            clearText = in.nextLine();
            //clearText = "HI";
            //Thread.sleep(100);

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey aesSecretKey = keyGenerator.generateKey();
            Cipher aesCipher = Cipher.getInstance("AES");

            aesCipher.init(Cipher.ENCRYPT_MODE, aesSecretKey);

            String AESCryptedText = Base64.encode(aesCipher.doFinal(clearText.getBytes()));

            privPacket.data = AESCryptedText;


            privPacket.AESkey = Base64.encode(cipher.doFinal(aesSecretKey.getEncoded()));


            privPacket.publicKey = Base64.encode(keyPair.getPublic().getEncoded());

            String sig;

            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

            sig = (new HexBinaryAdapter()).marshal(md.digest(clearText.getBytes()));
            sig = Base64.encode(cipher.doFinal(sig.getBytes()));

            privPacket.sig = sig;
            System.out.println("Transmitting Packet: " + gson.toJson(privPacket));
            pw.println(gson.toJson(privPacket));
        }

    }
}
