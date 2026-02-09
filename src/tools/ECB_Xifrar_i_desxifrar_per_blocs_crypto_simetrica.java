package tools;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ECB_Xifrar_i_desxifrar_per_blocs_crypto_simetrica {

    public static void main(String[] args) {

        //XIFRAR DADES
        SecretKey key = keygenKeyGeneration(128);
        byte[] output = encryptData(key, "data to encrypt".getBytes());
        System.out.println(output);
        
        //DESXIFRAR DADES
        output = decryptData(key,output);
        String s = new String(output, StandardCharsets.UTF_8);
        System.out.println(s);

    }

    public static byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }
    
        public static byte[] decryptData(SecretKey sKey, byte[] dataEncrypted) {
        byte[] Data = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            Data = cipher.doFinal(dataEncrypted);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return Data;
    }

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

}
