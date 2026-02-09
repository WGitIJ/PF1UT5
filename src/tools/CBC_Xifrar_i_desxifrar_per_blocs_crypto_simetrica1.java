package tools;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1 {
    
    public static final byte[] IV_PARAM = {0x00, 0x01, 0x02, 0x03, 
                                         0x04, 0x05, 0x06, 0x07, 
                                         0x08, 0x09, 0x0A, 0x0B, 
                                         0x0C, 0x0D, 0x0E, 0x0F};

    public static void main(String[] args) {        

        //XIFRAR DADES
        SecretKey key = keygenKeyGeneration(128);
        byte[] output = encryptData(key, "data to encrypt".getBytes());
        System.out.println(output);

        //DESXIFRAR DADES
        output = decryptData(key, output);
        String s = new String(output, StandardCharsets.UTF_8);
        System.out.println(s);

    }

    public static byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(SecretKey sKey, byte[] dataEncrypted) {
        byte[] Data = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
            Data = cipher.doFinal(dataEncrypted);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return Data;
    }

    // Este metodo lo que hace es generar una clave secreta con el algoritmo AES, y devuelve la clave generada
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
