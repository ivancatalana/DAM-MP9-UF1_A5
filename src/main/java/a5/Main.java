package a5;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        // Generar par de claves RSA de 1024 bits
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();
        KeyPair keyPair = utilitatsXifrar.randomGenerate(1024);

        // Obtener la clave pública y privada
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Mostrar información sobre las claves
        System.out.println("Clave pública: " + publicKey);
        System.out.println("Clave privada: " + privateKey);

        // Obtener el mensaje a cifrar del usuario
        Scanner scanner = new Scanner(System.in);
        System.out.print("Introduce el mensaje a cifrar: ");
        String mensaje = scanner.nextLine();

        // Generar una clave simétrica utilizando la contraseña ingresada por el usuario
        System.out.print("Introduce una contraseña: ");
        String password = scanner.nextLine();
        SecretKey secretKey = utilitatsXifrar.passwordKeyGeneration(password, 128); // Tamaño de clave: 128 bits

        // Cifrar la clave simétrica utilizando la clave pública
        byte[] claveCifrada = utilitatsXifrar.encryptDataPublic(publicKey, secretKey.getEncoded());

        // Cifrar el mensaje utilizando la clave simétrica
        byte[] mensajeCifrado = utilitatsXifrar.encryptData(secretKey, mensaje.getBytes());

        System.out.println("Clave simétrica cifrada: " + new String(claveCifrada));
        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));

        // Descifrar la clave simétrica utilizando la clave privada
        byte[] claveDescifrada = utilitatsXifrar.decryptDataPublic(privateKey, claveCifrada);
        SecretKey secretKeyDescifrada = new SecretKeySpec(claveDescifrada, "AES");

        // Descifrar el mensaje utilizando la clave simétrica descifrada
        byte[] mensajeDescifrado = utilitatsXifrar.decryptData(secretKeyDescifrada, mensajeCifrado);
        System.out.println("Mensaje descifrado: " + new String(mensajeDescifrado));
    }
}
