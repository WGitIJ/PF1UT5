package models;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Servidor {
    public static void main(String[] args) {
        try(ServerSocket servidor = new ServerSocket(1234);
        ) {
            System.out.println("Servidor inicilizado. Esperando conexiones...");

            Socket socket = servidor.accept();
            DataInputStream reader = new DataInputStream(socket.getInputStream());
            DataOutputStream writer = new DataOutputStream(socket.getOutputStream());

            System.out.println("Cliente conectado desde " + socket.getInetAddress().getHostAddress());

            //Enviar llave pública al cliente
            KeyPair keys = keyPair();
            byte[] publicKeyBytes = keys.getPublic().getEncoded();
            writer.writeInt(publicKeyBytes.length);
            writer.write(publicKeyBytes);
            writer.flush();

            //Recibir los datos cifrados del cliente
            int length = reader.readInt();
            byte[] encryptedData = new byte[length];
            reader.readFully(encryptedData);
            System.out.println("Datos cifrados recibidos del cliente.");

            //Descifrar los datos con la clave privada
            byte[] decryptedData = tools.Xifrar_i_desxifrar_crypto_asimetrica_RSA.decryptData(encryptedData, keys.getPrivate());

            // Validar que los datos descifrados tengan al menos 8 bytes para contener la longitud de la clave y la longitud del hash.
            DataInputStream keyDis = new DataInputStream(new ByteArrayInputStream(decryptedData));
            int keyLength = keyDis.readInt();
            if (keyLength <= 0) {
                throw new IllegalStateException("Longitud de clave inválida.");
            }
            byte[] secretKeyBytes = new byte[keyLength];
            keyDis.readFully(secretKeyBytes);

            int hashLength = keyDis.readInt();
            if (hashLength <= 0) {
                throw new IllegalStateException("Longitud de hash inválida.");
            }
            byte[] receivedHash = new byte[hashLength];
            keyDis.readFully(receivedHash);

            byte[] hash = MessageDigest.getInstance("SHA-256").digest(secretKeyBytes);

            //Verificar integridad
            if (Arrays.equals(hash, receivedHash)) {
                System.out.println("Integridad verificada. La clave AES es válida y no ha sido alterada.");
            } else {
                System.out.println("Integridad comprometida. La clave AES puede haber sido alterada.");
                return;
            }

            // Crear clave simétrica AES a partir de los bytes recibidos.
            SecretKey sharedKey = new SecretKeySpec(secretKeyBytes, "AES");
            System.out.println("Esperando mensajes cifrados con la clave compartida...");

            // El servidor seguirá recibiendo mensajes cifrados hasta que el cliente indique que desea finalizar la comunicación.
            while (true) {
                int msgLength = reader.readInt();
                if (msgLength <= 0) {
                    System.out.println("Fin de comunicación solicitado por el cliente.");
                    break;
                }

                byte[] encryptedMsg = new byte[msgLength];
                reader.readFully(encryptedMsg);

                // Descifrar el mensaje utilizando la clave compartida.
                byte[] decryptedMsgPayload = tools.CBC_Xifrar_i_desxifrar_per_blocs_crypto_simetrica1.decryptData(sharedKey, encryptedMsg);

                // Validar que el mensaje descifrado tenga al menos 8 bytes para contener la longitud del texto y la longitud del hash.
                if (decryptedMsgPayload == null || decryptedMsgPayload.length < 8) {
                    System.out.println("Mensaje inválido recibido.");
                    continue;
                }

                // Utilizar DataInputStream para leer la longitud del texto, el texto en sí, la longitud del hash y el hash del mensaje.
                DataInputStream msgDis = new DataInputStream(new ByteArrayInputStream(decryptedMsgPayload));
                int textLength = msgDis.readInt();
                if (textLength <= 0) {
                    System.out.println("Longitud de texto inválida.");
                    continue;
                }

                // Leer el texto del mensaje.
                byte[] textBytes = new byte[textLength];
                msgDis.readFully(textBytes);

                // Leer la longitud del hash y el hash del mensaje.
                int receivedHashLength = msgDis.readInt();
                if (receivedHashLength <= 0) {
                    System.out.println("Longitud de hash inválida.");
                    continue;
                }
                byte[] receivedTextHash = new byte[receivedHashLength];
                msgDis.readFully(receivedTextHash);

                // Calcular el hash del texto recibido para verificar su integridad.
                byte[] generatedTextHash = MessageDigest.getInstance("SHA-256").digest(textBytes);
                if (Arrays.equals(generatedTextHash, receivedTextHash)) {
                    System.out.println("Mensaje recibido OK: " + new String(textBytes, StandardCharsets.UTF_8));
                } else {
                    System.out.println("Integridad comprometida en el mensaje recibido.");
                }
            }


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair keyPair(){
        KeyPair keys = null;
        try {
            keys = tools.Xifrar_i_desxifrar_crypto_asimetrica_RSA.randomGenerate(2048);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return keys;
    }
}
