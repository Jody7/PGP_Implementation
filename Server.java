import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.google.gson.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Server {

    public static void main(String[] args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        ServerSocket sSocket = null;
        Socket cSocket = null;

        Packet packet1 = new Packet();


        try {
            sSocket = new ServerSocket(7777);
            cSocket = sSocket.accept();
        } catch (IOException e) {
            System.err.println("socket failure");
        }

        PrintWriter pw = new PrintWriter(cSocket.getOutputStream(), true);
        BufferedReader br = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));

        KeyPair keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        } catch (Exception e) {
            System.err.println("RSA keypair generation failed: " + e.toString());
        }


        final Cipher cipher = Cipher.getInstance("RSA");

        final Cipher aesCipher = Cipher.getInstance("AES");

        byte[] privateKey;

        packet1.publicKey = Base64.encode(keyPair.getPublic().getEncoded());
        packet1.sig = (new HexBinaryAdapter()).marshal(md.digest(packet1.publicKey.getBytes()));
        packet1.PublicOrPrivate = "public";

        Gson gson = new GsonBuilder().create();
        Packet privPacket = null;

        System.out.println("TRANSITING PUBLIC PACKET: " + gson.toJson(packet1));
        pw.println(gson.toJson(packet1));

        privateKey = keyPair.getPrivate().getEncoded();

        PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));


        while(true) {


            String cipherText = br.readLine();
            System.out.println("RECEIVED CIPHER-TEXT: " + cipherText);
            privPacket = gson.fromJson(cipherText,Packet.class);

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            privPacket.AESkey = Base64.encode(cipher.doFinal(Base64.decode(privPacket.AESkey)));
            //decrypt AES key with PGP

            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(privPacket.publicKey)));
            SecretKey aesSecretKey = new SecretKeySpec(Base64.decode(privPacket.AESkey), 0, Base64.decode(privPacket.AESkey).length, "AES");

            aesCipher.init(Cipher.DECRYPT_MODE, aesSecretKey);

            String plainText = new String(aesCipher.doFinal(Base64.decode(privPacket.data)));
            //decrypt regular data with AES key


            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] sigPlain = cipher.doFinal(Base64.decode(privPacket.sig));
            String sigPlainS = new String(sigPlain);
            System.out.println("PLAIN SIG: " + sigPlainS);
            if((new HexBinaryAdapter()).marshal(md.digest(plainText.getBytes())).equals(sigPlainS)) {
                //GOOD
            }else{
                System.out.println("SIG FAILED");
                System.exit(1);
            }
            cipher.init(Cipher.DECRYPT_MODE, pk);



            System.out.println("DECRYPTING WITH PGP PRIVATE KEY: " + Base64.encode(privateKey));
            System.out.println("AES KEY OBTAINED: " + privPacket.AESkey);
            System.out.println("AES ENCRYPTED CIPHERTEXT: " + privPacket.data);
            System.out.println("---PT DT--- DECRYPTED WITH AES KEY: " + plainText);

        }


    }

}
