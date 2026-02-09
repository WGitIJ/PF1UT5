package models;

import tools.CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import static tools.hash.passwordKeyGeneration;

public class Client{
    static void main(String[] args) {
        try(Socket socket = new Socket("localhost", 1111)) {
            System.out.println("Conectado al servidor en " + socket.getInetAddress().getHostAddress());
            byte[] publicKeyBytes = new byte[256]; // Tamaño típico de una clave RSA de 2048 bits
            socket.getInputStream().read(publicKeyBytes);
            System.out.println("Clave pública recibida del servidor.");

            //Generamos la clave simétrica
            SecretKey secretKey = generateSymmetricKey();
            //Hasheamos la clave simétrica
            SecretKey hashSecretKey = hashPassword(secretKey);
            //Ciframos la clave simétrica con la clave pública del servidor
            byte[] encryptedKey = encryptData(hashSecretKey, publicKeyBytes);
            //Enviamos la clave cifrada al servidor
            socket.getOutputStream().write(encryptedKey);
        }
        catch (UnknownHostException e) {
            System.err.println("Host desconocido: " + e.getMessage());
        }
        catch (IOException e) {
            System.err.println("Error de E/S: " + e.getMessage());
        }
    }

    public static SecretKey generateSymmetricKey() {
        SecretKey secretKey = CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1.keygenKeyGeneration(256);
        return secretKey;
    }

    public static SecretKey hashPassword(SecretKey secretKey) {
        byte[] keyBytes = secretKey.getEncoded();
        SecretKey sk = passwordKeyGeneration(new String(keyBytes), 256);
        return sk;
    }

    public static byte[] encryptData(SecretKey secretKey, byte[] data) {
        byte[] encryptedData = CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1.encryptData(secretKey, data);
        return encryptedData;
    }
}