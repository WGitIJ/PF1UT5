package models;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 1234);
             DataInputStream reader = new DataInputStream(socket.getInputStream());
             DataOutputStream writer = new DataOutputStream(socket.getOutputStream())) {

            System.out.println("Cliente conectado al servidor.");

            // Recibir clave pública del servidor
            int length = reader.readInt();
            byte[] publicKeyBytes = new byte[length];
            reader.readFully(publicKeyBytes);
            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // Generar clave simétrica AES
            SecretKey secretKey = tools.CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1.keygenKeyGeneration(128);
            byte[] secretKeyBytes = secretKey.getEncoded();

            // Hash real sobre els bytes de la clau per a verificar integritat.
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(secretKeyBytes); //Comparar con el hash recibido en el servidor para verificar que la clave no ha sido alterada.

            // Empaquetar clave + hash con DataOutputStream.
            ByteArrayOutputStream keyBaos = new ByteArrayOutputStream();
            DataOutputStream keyDos = new DataOutputStream(keyBaos);
            keyDos.writeInt(secretKeyBytes.length);
            keyDos.write(secretKeyBytes);
            keyDos.writeInt(hash.length);
            keyDos.write(hash);
            keyDos.flush();
            byte[] keyPayload = keyBaos.toByteArray();

            // Cifrar con clave pública del servidor
            byte[] encrypted = tools.Xifrar_i_desxifrar_crypto_asimetrica_RSA.encryptData(keyPayload, publicKey);

            // Enviar al servidor
            writer.writeInt(encrypted.length);
            writer.write(encrypted);
            writer.flush();

            System.out.println("Clave AES enviada de forma segura al servidor.");

            // Enviar mensajes al servidor
            Scanner scanner = new Scanner(System.in);
            System.out.println("Escribe palabras/mensajes para enviar (\"exit\" para terminar):");

            // El cliente seguirá enviando mensajes hasta que el usuario escriba "exit".
            while (true) {
                String text = scanner.nextLine();
                if ("exit".equalsIgnoreCase(text)) {
                    writer.writeInt(0);
                    writer.flush();
                    break;
                }

                // Calcular hash del mensaje para integridad.
                byte[] textBytes = text.getBytes(StandardCharsets.UTF_8); // Convertir el texto a bytes usando UTF-8.
                byte[] textHash = MessageDigest.getInstance("SHA-256").digest(textBytes);

                // Empaquetar mensaje + hash con DataOutputStream.
                ByteArrayOutputStream msgBaos = new ByteArrayOutputStream();
                DataOutputStream msgDos = new DataOutputStream(msgBaos);

                // Escribir la longitud del mensaje y el mensaje en sí.
                msgDos.writeInt(textBytes.length);
                msgDos.write(textBytes);
                msgDos.writeInt(textHash.length);
                msgDos.write(textHash);
                msgDos.flush();
                byte[] msgHash = msgBaos.toByteArray(); //

                // Cifrar el mensaje con la clave AES compartida.
                byte[] encryptedMessage = tools.CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1.encryptData(secretKey, msgHash);
                writer.writeInt(encryptedMessage.length);
                writer.write(encryptedMessage);
                writer.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
