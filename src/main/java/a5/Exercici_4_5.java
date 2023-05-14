package a5;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class Exercici_4_5 {

        public static PublicKey getPublicKey(String filePath) throws Exception {
            FileInputStream fis = new FileInputStream(filePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(fis);
            PublicKey publicKey = certificate.getPublicKey();
            fis.close();
            return publicKey;
        }

        public static PublicKey getPublicKey(KeyStore keyStore, String alias, String password) throws Exception {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
                    new KeyStore.PasswordProtection(password.toCharArray()));
            return privateKeyEntry.getCertificate().getPublicKey();
        }

        public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        }

        public static void main(String[] args) {
            try {
                // Obtener la PublicKey de un archivo de certificado (.cer)
                String certificateFile = "certificado.cer";
                PublicKey publicKeyFromFile = getPublicKey(certificateFile);
                System.out.println("PublicKey obtenida del archivo de certificado:");
                System.out.println(publicKeyFromFile);

                // Obtener la PublicKey de una clave asimétrica en el keystore
                String keystoreFile = "keystore.p12";
                String keystorePassword = "keystorePassword";
                String keyAlias = "myKey";
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                FileInputStream fis = new FileInputStream(keystoreFile);
                keyStore.load(fis, keystorePassword.toCharArray());
                fis.close();
                PublicKey publicKeyFromKeystore = getPublicKey(keyStore, keyAlias, keystorePassword);
                System.out.println("PublicKey obtenida del keystore:");
                System.out.println(publicKeyFromKeystore);

                // Firmar datos utilizando una PrivateKey
                byte[] dataToSign = "Datos a firmar".getBytes();
                String privateKeyFile = "privateKey.der";
                FileInputStream privateKeyFis = new FileInputStream(privateKeyFile);
                byte[] privateKeyBytes = new byte[privateKeyFis.available()];
                privateKeyFis.read(privateKeyBytes);
                privateKeyFis.close();
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                byte[] signature = signData(dataToSign, privateKey);
                System.out.println("Firma generada:");
                System.out.println(Arrays.toString(signature));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


}
