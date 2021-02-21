import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;



class EncryptFile {
    public static Signature signatureS = null;
    public static byte[] SIG;


    public static void createConfigurationFile(byte[] encrypt_symmetric_key, byte[] iv, byte[] signature,String configuration_file_path ) throws IOException {

            try {
                FileOutputStream outputStreamFile = new FileOutputStream(configuration_file_path);
                outputStreamFile.write(encrypt_symmetric_key);
                outputStreamFile.write(signature);
                outputStreamFile.write(iv);
                outputStreamFile.flush();
                outputStreamFile.close();


            } catch (IOException e) {
                System.out.println("writeEncryptionPropertiesToFile function failed");
                e.printStackTrace();
            }
    }

    public static void createSignature (byte[] encrypted_data,String encrypter_keystore_path, String keystore_type,String encrypter_keystore_pass,String encrypter_private_key_alias,String encrypter_signature_algorithm ) throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException, SignatureException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException {
        File file = new File(encrypter_keystore_path);
        FileInputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(keystore_type);
        String password = encrypter_keystore_pass;
        char[] passwd = password.toCharArray();
        keystore.load(is, passwd);
//        is.close();
        PrivateKey myPrivateKey = (PrivateKey) keystore.getKey(encrypter_private_key_alias, password.toCharArray());

        Signature dsa = Signature.getInstance(encrypter_signature_algorithm);
        dsa.initSign(myPrivateKey);
        dsa.update(encrypted_data);
        signatureS = dsa;
        SIG = dsa.sign();
    }

    public static byte[] encryptAESkey(byte[] AESplainKey,String encrypter_keystore_path,String keystore_type,String encrypter_keystore_pass,String destenation_cert_alias,String encrypter_asymmetric_algorithm,String encrypter_asymmetric_algorithm_provider) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, KeyStoreException, CertificateException, InvalidKeyException, NoSuchProviderException {

        File file = new File(encrypter_keystore_path);
        FileInputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(keystore_type);
        String password = encrypter_keystore_pass;
        char[] passwd = password.toCharArray();
        keystore.load(is, passwd);

        Certificate cert = keystore.getCertificate(destenation_cert_alias);
        PublicKey publicKey = cert.getPublicKey();
        Cipher cipher = Cipher.getInstance(encrypter_asymmetric_algorithm,encrypter_asymmetric_algorithm_provider);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(AESplainKey);

        return result;

    }


}