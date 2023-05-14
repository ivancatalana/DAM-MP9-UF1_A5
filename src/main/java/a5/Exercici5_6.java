package a5;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class Exercici5_6 {

    public static byte[] signData(byte[] data, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (Exception ex) {
            System.err.println("Error firmando los datos: " + ex);
        }
        return null;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey publicKey) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initVerify(publicKey);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validando los datos: " + ex);
        }
        return isValid;
    }

    public static void main(String[] args) {
        try {
            // Ruta del archivo del Keystore
            String keystorePath = "/Users/travisnoderlay/SDKS/jdk-18_macos-x64_bin/jdk-18.0.2.1.jdk/Contents/Home/bin/keystore.jks";
            // Contraseña del Keystore
            String keystorePassword = "Usuario1";
            // Alias de la clave privada en el Keystore
            String alias = "mykey";

            // Cargar el Keystore desde el archivo
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keystorePath);
            keyStore.load(fis, keystorePassword.toCharArray());
            fis.close();

            // Obtener la clave privada del Keystore
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());

            // Datos a firmar
            byte[] data = "Datos a firmar".getBytes();

            // Firmar los datos
            byte[] signature = signData(data, privateKey);

            // Imprimir la firma
            if (signature != null) {
                System.out.println("Firma generada: " + bytesToHex(signature));
            } else {
                System.out.println("Error al generar la firma.");
            }

            // Obtener la clave pública del Keystore
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

            // Validar la firma
            boolean isValidSignature = validateSignature(data, signature, publicKey);
            System.out.println("La firma es válida: " + isValidSignature);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Función auxiliar para convertir un arreglo de bytes a una representación hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
