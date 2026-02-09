package tools;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class Xifrar_i_desxifrar_crypto_asimetrica_RSA {

    public static void main(String[] args) {

        KeyPair pk = randomGenerate(2048);
        PrivateKey priv = pk.getPrivate();
        PublicKey pub = pk.getPublic();

        //System.out.println(priv.toString());
        //System.out.println(pub.toString());

        byte [] output = encryptData("text to encrypt".getBytes(), pub);
        String s = new String(output, StandardCharsets.UTF_8);
        System.out.println(s);
        
        output = decryptData(output, priv);
        s = new String(output, StandardCharsets.UTF_8);
        System.out.println(s);
    }

    //Este metodo lo que hace es generar un par de claves (publica y privada) con el algoritmo RSA, y devuelve el par de claves generado
    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator .getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    // Este metodo lo que hace es cifrar el mensaje con la clave publica, y devuelve el mensaje cifrado en bytes
    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    // Este metodo lo que hace es desifrar el mensaje cifrado con la clave privada, y devuelve el mensaje original en bytes
    public static byte[] decryptData(byte[] dataEncrypted, PrivateKey priv) {
        byte[] Data = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, priv);
            Data = cipher.doFinal(dataEncrypted);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return Data;
    }
}
