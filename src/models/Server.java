package models;

import tools.Xifrar_i_desxifrar_crypto_asimetrica_RSA;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Arrays;

import static tools.hash.passwordKeyGeneration;

public class Server {
    static void main(String[] args) {
        try(ServerSocket servidor = new ServerSocket(1111)) {
            System.out.println("Servidor iniializado. Esperando conexiones...");

            Socket socket = servidor.accept();
            System.out.println("Cliente conectado desde " + socket.getInetAddress().getHostAddress());

            //Conseguimos el par de claves
            KeyPair keyPair = keys();
            System.out.println("Par de claves generado.");

            //Enviamos la clave publica al cliente
            socket.getOutputStream().write(keyPair.getPublic().getEncoded());
            System.out.println("Clave pública enviada al cliente.");

            //Recibimos la clave cifrada del cliente
            byte[] encryptedKey = new byte[256];
            socket.getInputStream().read(encryptedKey);
            System.out.println("Clave cifrada recibida del cliente.");

            //Desciframos la clave simétrica con la clave privada
            decryptData(encryptedKey, keyPair);
            System.out.println("Clave simétrica descifrada con la clave privada.");

            //Hasheamos la clave simétrica descifrada
            SecretKey hashedKey = hashKey(encryptedKey);

            //Comparamos si son iguales la clave simétrica original y la clave simétrica hasheada
            compareKeys(hashedKey, hashKey(encryptedKey));

        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair keys() {
        KeyPair keyPair = Xifrar_i_desxifrar_crypto_asimetrica_RSA.randomGenerate(2048);
        return keyPair;
    }

    public static void decryptData(byte[] encryptedKey, KeyPair keyPair) {
        byte[] decryptedKey = Xifrar_i_desxifrar_crypto_asimetrica_RSA.decryptData(encryptedKey, keyPair.getPrivate());
        System.out.println("Clave simétrica descifrada: " + new String(decryptedKey));
    }

    public static SecretKey hashKey(byte[] decryptedKey) {
        SecretKey hashedKey = passwordKeyGeneration(new String(decryptedKey), 256);
        System.out.println("Clave simétrica hasheada: " + new String(hashedKey.getEncoded()));
        return hashedKey;
    }

    public static boolean compareKeys(SecretKey hashedKey, SecretKey originalKey) {
        boolean keysMatch = Arrays.equals(hashedKey.getEncoded(), originalKey.getEncoded());
        System.out.println("¿Las claves coinciden? " + keysMatch);
        return keysMatch;
    }
}