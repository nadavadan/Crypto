//Nadav Tal
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class JavaCryptoProgram {

//General parameters
public static String keystore_type ="jks";

// Encryption parameters
public static String file_to_encrypt_path = "C:\\java\\test_plain_text.txt";
public static String configuration_file_path = "ConfigurationFile.txt";
public static String encrypted_file_path = "CipherText.txt";
public static String encrypter_keystore_path = "C:\\Program Files\\Java\\jdk-15\\bin\\keystore1.jks";
public static String encrypter_keystore_pass = "--";
public static String encrypter_private_key_alias = "firstkey";
public static String destenation_cert_alias = "public2.cert";
public static String symmetric_algorithm = "AES";
public static String encrypter_asymmetric_algorithm = "RSA/ECB/PKCS1Padding";
public static String encrypter_asymmetric_algorithm_provider= "SunJCE";
public static String encrypter_signature_algorithm = "SHA256withRSA";
public static String encrypter_symmetric_algorithm_provider= "SunJCE";
public static String padding_method = "PKCS5Padding";
public static String encrypt_mode = "CBC";


//Decryption parameters
public static String props_file_path = "ConfigurationFile.txt";
public static String file_to_decrypt_path = "CipherText.txt";
public static String decrypted_file_path = "PlainText.txt";
public static String decryption_symmetric_algrithm = "AES";
public static String decryption_asymmetric_provider = "SunJSSE";
public static String dcryption_mode = "CBC";
public static String decryption_padding = "PKCS5Padding";
public static String decrypter_keystore_path = "C:\\Program Files\\Java\\jdk-15\\bin\\keystore2.jks";
public static String decrypter_keystore_pass = "--";
public static String decrypter_privat_key_alias = "secondkey";
public static String decrypter_assymetric_algorithm = "RSA/ECB/PKCS1Padding";
public static String decrypter_asymmetric_algorithm_provider= "SunJCE";
public static String sender_cert_alias = "public.cert";
public static String decrypter_signature_algorithm = "SHA256withRSA";



    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException, CertificateException, SignatureException, InvalidAlgorithmParameterException, NoSuchProviderException {

//        Java function to print which java crypto providers are available

//         Provider[] providers = Security.getProviders();
//        for(int i = 0; i < providers.length; i++) {
//            System.out.println(providers[i].toString());
//        }




//        Uncomment to Encrypt

//        Uncomment to encrypt
//        Encrypt();

//        Uncomment to decrypt
        Decrypt();

    }

    public static void Encrypt() {

        try {

            //AES symmetric key generator
            KeyGenerator keygen = KeyGenerator.getInstance(symmetric_algorithm);
            Key k = keygen.generateKey();

            //Encrypt mode cypher instance
            Cipher aes = Cipher.getInstance(symmetric_algorithm+"/"+encrypt_mode+"/"+padding_method,encrypter_symmetric_algorithm_provider);
            aes.init(Cipher.ENCRYPT_MODE,k);

//Build cypher input stream and then outputStream
            FileInputStream fis = new FileInputStream(file_to_encrypt_path);
            CipherInputStream cis = new CipherInputStream(fis, aes);
            FileOutputStream fos = new FileOutputStream(encrypted_file_path);
            byte[] b = new byte[8];
            int i = cis.read(b);
            while (i != -1) { fos.write(b, 0, i); i = cis.read(b); }
            fos.flush();
            fos.close();

//            Read into byte array the cipherText

            FileInputStream in = new FileInputStream(encrypted_file_path);
            byte[] cnryptData = in.readAllBytes();

//            Java function to create configuration file
            EncryptFile.createSignature(cnryptData,encrypter_keystore_path,keystore_type,encrypter_keystore_pass,encrypter_private_key_alias,encrypter_signature_algorithm);
            byte[] encryptedAESkey = EncryptFile.encryptAESkey(k.getEncoded(),encrypter_keystore_path,keystore_type,encrypter_keystore_pass,destenation_cert_alias,encrypter_asymmetric_algorithm,encrypter_asymmetric_algorithm_provider);

//            Java function to print props into configuration file
            EncryptFile.createConfigurationFile(encryptedAESkey, EncryptFile.SIG,aes.getIV(),configuration_file_path);

//Total general test:


//            Initialize cypher to encrymt mode
            aes.init(Cipher.DECRYPT_MODE, k,aes.getParameters());
            String decrypted = new String(aes.doFinal(cnryptData));
            System.out.println(decrypted);

//            Connect to keystore
            File file2 = new File(decrypter_keystore_path);
            FileInputStream is2 = new FileInputStream(file2);
            KeyStore keystore2 = KeyStore.getInstance(keystore_type);
            String password = encrypter_keystore_pass;
            char[] passwd = password.toCharArray();
            keystore2.load(is2, passwd);

//            Load sender Certificate
            Certificate cert = keystore2.getCertificate(sender_cert_alias);

//            Get public key and create signature
            PublicKey publicKey = cert.getPublicKey();
            Signature dsa = Signature.getInstance(encrypter_signature_algorithm);
            dsa.initVerify(publicKey);
            dsa.update(cnryptData);
            boolean verifies = dsa.verify(EncryptFile.SIG);
            System.out.println("Signature validiti inside JavaCryptoProgram: " + verifies );
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void Decrypt() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, UnrecoverableKeyException, BadPaddingException, KeyStoreException, CertificateException, SignatureException, InvalidAlgorithmParameterException, NoSuchProviderException {
     //   read props from configuration file
        byte[] AES = DecryptFile.readConfigurationFile(props_file_path);


//       Decrypt AES key
        byte[] plainAESkey = DecryptFile.DecryptKey(AES,decrypter_keystore_path,keystore_type,decrypter_keystore_pass,decrypter_privat_key_alias,decrypter_assymetric_algorithm,decrypter_asymmetric_algorithm_provider);
        SecretKey originalKey = new SecretKeySpec(plainAESkey, 0, plainAESkey.length, decryption_symmetric_algrithm);

//        Read The encrypted data from file
        byte[] encrypted_data = Files.readAllBytes(Paths.get(file_to_decrypt_path));
//        try{

//        Checks signature validity

            if(!DecryptFile.ValidateSignature(encrypted_data,decrypter_keystore_path,keystore_type,decrypter_keystore_pass,sender_cert_alias,decrypter_signature_algorithm)) {

//                Initialize cypher and build cypherInputStream
                Cipher aes = Cipher.getInstance(decryption_symmetric_algrithm+"/"+dcryption_mode+"/"+decryption_padding);
                aes.init(Cipher.DECRYPT_MODE, originalKey, new IvParameterSpec(DecryptFile.IV));
                FileInputStream fis = new FileInputStream(file_to_decrypt_path);
                CipherInputStream cis = new CipherInputStream(fis, aes);

//                Build outputStream
                FileOutputStream fos = new FileOutputStream(decrypted_file_path);
                byte[] b = new byte[8];
                int i = cis.read(b);
                while (i != -1) { fos.write(b, 0, i); i = cis.read(b); }
            }
//        }
//        catch (SignatureException | NoSuchProviderException e){
//            System.out.println("Signature not valid");
//        }

    }
}
