package a5;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Scanner;

public class Exercici2_3 {


        public static void main(String[] args) {
            try {
                // Obtener la información del usuario
                Scanner scanner = new Scanner(System.in);
                System.out.print("Ingrese la ruta del archivo del keystore: ");
                String keystorePath = scanner.nextLine();
                System.out.print("Ingrese la contraseña del keystore: ");
                String keystorePassword = scanner.nextLine();

                // Genera una nueva clave simétrica
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(128);
                SecretKey secretKey = keyGen.generateKey();

                // Crea una entrada de clave simétrica en el keystore
                String alias = "mykey";
                char[] keyPassword = "keyPassword".toCharArray(); // Contraseña de la clave
                KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);

                // Cargar el keystore desde el archivo
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                FileInputStream fis = new FileInputStream(keystorePath);
                keyStore.load(fis, keystorePassword.toCharArray());
                fis.close();

                // Agrega la nueva clave simétrica al keystore
                keyStore.setEntry(alias, entry, new KeyStore.PasswordProtection(keyPassword));

                // Guarda el keystore de nuevo en el archivo (opcional)
                FileOutputStream fos = new FileOutputStream(keystorePath);
                keyStore.store(fos, keystorePassword.toCharArray());
                fos.close();

                // Obtener el tipo de keystore
                String keystoreType = keyStore.getType();
                System.out.println("Tipo de keystore: " + keystoreType);

                // Obtener el tamaño del almacén (número de claves)
                int size = keyStore.size();
                System.out.println("Tamaño del almacén: " + size);

                // Obtener los alias de las claves
                Enumeration<String> aliases = keyStore.aliases();
                System.out.println("Alias de las claves almacenadas:");
                while (aliases.hasMoreElements()) {
                    alias = aliases.nextElement();
                    System.out.println("- " + alias);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
}