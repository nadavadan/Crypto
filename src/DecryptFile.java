import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class DecryptFile {
  public static byte[] AES = new byte[256];
  public static byte[] SIG = new byte[256] ;
  public static byte[] IV = new byte[16];
  public static byte[] RESULT= new byte[256] ;





        public static byte[] readConfigurationFile(String props_file_path) {
                try {
                        FileInputStream properties = new FileInputStream(props_file_path);
                        properties.read(AES);
                        properties.read(SIG);
                        properties.read(IV);
                        properties.close();
                } catch (IOException e) {
                        System.out.println("readProperties function failed");
                        e.printStackTrace();
                }

                return AES;
        }

        public static byte[] DecryptKey(byte[] cipherAES,String decrypter_keystore_path,String keystore_type,String decrypter_keystore_pass,String decrypter_privat_key_alias,String decrypter_assymetric_algorithm,String decrypter_asymmetric_algorithm_provider) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, KeyStoreException, CertificateException, InvalidKeyException, UnrecoverableKeyException, NoSuchProviderException {
//cipherAES can also be used as argument (currently from static variable)

                //Connect to decrypter keystore
                File file = new File(decrypter_keystore_path);
                FileInputStream is = new FileInputStream(file);
                KeyStore keystore = KeyStore.getInstance(keystore_type);
                String password = decrypter_keystore_pass;
                char[] passwd = password.toCharArray();
                keystore.load(is, passwd);

//                bring my private key to decrypt with RSA the AES symmetric key.
                PrivateKey myPrivateKey = (PrivateKey) keystore.getKey(decrypter_privat_key_alias, password.toCharArray());


//                initialize cipher to encrypt the symmetric key
                Cipher aes = Cipher.getInstance(decrypter_assymetric_algorithm,decrypter_asymmetric_algorithm_provider);
                aes.init(Cipher.DECRYPT_MODE,myPrivateKey);
                RESULT = aes.doFinal(AES);

                return RESULT;
        }


        public static boolean ValidateSignature(byte[] cypher,String decrypter_keystore_path,String keystore_type,String decrypter_keystore_pass,String sender_cert_alias,String decrypter_signature_algorithm) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

//              Connect keystore
                File file = new File(decrypter_keystore_path);
                FileInputStream is = new FileInputStream(file);
                KeyStore keystore = KeyStore.getInstance(keystore_type);
                String password = decrypter_keystore_pass;
                char[] passwd = password.toCharArray();
                keystore.load(is, passwd);

//              Get ceritficate
                Certificate cert = keystore.getCertificate(sender_cert_alias);
                PublicKey publicKey = cert.getPublicKey();


//              Verify sifnature
                Signature sig = Signature.getInstance(decrypter_signature_algorithm);
                sig.initVerify(publicKey);
                sig.update(cypher);
                boolean verifies = sig.verify(SIG);
                System.out.println("Vaildate signature after reading props: "+verifies);
                return verifies;
        }


}
