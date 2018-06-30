
package org.cryptotester.mylab.security;

import org.apache.log4j.Logger;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.Validator;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.errors.EncryptionException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Locale;
import java.util.regex.Pattern;


public class SecAlgorithms {


    private static Pattern[] patterns = new Pattern[]{
            // Script fragments
            Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
            // src='...'
            Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // lonely script tags
            Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // eval(...)
            Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // expression(...)
            Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // javascript:...
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            // vbscript:...
            Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
            // onload(...)=...
            Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL)
    };


    private static final Logger logger = Logger.getLogger(SecAlgorithms.class);

    public SecAlgorithms() {

        super();

    }


    public static String getESAPIEncoder() {

        String myMessage = "Hello World";
        String myEncodedMessage = ESAPI.encoder().encodeForHTML(myMessage);
        logger.info("My plaintext message: " + myMessage);
        logger.info("My html encoded message: " + myEncodedMessage);

        return myEncodedMessage;

    }


    public static void demoSymmetric() throws ParseException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidKeySpecException {


        logger.info("====================================.");
        logger.info("Begin executing method demoSymmetric.");

        String passphrase = "my passphrase is better than yours";
        byte[] salt = "choose a better salt".getBytes();


        logger.info("passphrase: " + passphrase);
        logger.info("salt text: choose a better salt");
        logger.info("generated salt byte array: " + salt.toString());

        int keyLength = 128;
        int iterations = 10000;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey tmp = factory.generateSecret(new PBEKeySpec(passphrase.toCharArray(), salt, iterations, keyLength));
        SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        logger.info("cipher: " + aes.getAlgorithm());
        logger.info("keyLength: " + keyLength);
        logger.info("the key: " + key.getEncoded());


        aes.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = aes.doFinal("mycleartextpassword".getBytes());

        logger.info("generated ciphertext from aes algorithm: " + ciphertext.toString());


        aes.init(Cipher.DECRYPT_MODE, key);
        String cleartext = new String(aes.doFinal(ciphertext));

        logger.info("Password in clear text: " + cleartext);

    }

    public static void demoSymmetric3DES() throws ParseException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        //ASCII 8 bits per character (1 byte characters) UTF-8
        //subtract parity bits from key length:
        //64 bits (8 bytes) - 8 = 56		- single key	- BROKEN in 56 hours!!!
        //128 bits (16 bytes) - 16 = 112	- two key		- COST 2^112 (EK1=64bits, DK2=64bits, EK3=K1)
        //192 bits (24 bytes) - 24 = 168	- three key

        //parity bits (check bits) are added to end of string to indicate whether count of "ones" is even or odd

        logger.info("====================================.");
        logger.info("Begin executing method demoSymmetric3DES.");


        int keyLength = 112;
        KeyGenerator keyGen = null;
        keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(keyLength); // key length 112 for two keys, 168 for three keys
        SecretKey secretKey = keyGen.generateKey();

        String strToEncrypt = "It's Friday!";

        logger.info("passphrase: " + strToEncrypt);

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        logger.info("cipher: " + cipher.getAlgorithm());
        logger.info("keyLength: " + keyLength);
        logger.info("the key: " + secretKey.getEncoded());

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedString = cipher.doFinal(strToEncrypt.getBytes());


        //can also add an iv:

        /*
        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        */

        logger.info("generated ciphertext from 3DES algorythm: " + encryptedString.toString());

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        String decryptedString = new String(cipher.doFinal(encryptedString));

        logger.info("3DES Encrypted Text: " + decryptedString);

    }


    public static String getSymmetricAESName() {


        Cipher aes = null;
        try {

            int keyLength = 128;
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keyLength);
            SecretKey secretKey = keyGen.generateKey();

            aes = Cipher.getInstance("AES");
            aes.init(Cipher.ENCRYPT_MODE, secretKey);

        } catch (NoSuchAlgorithmException e) {

            logger.error(e);

        } catch (NoSuchPaddingException e) {

            logger.error(e);

        } catch (InvalidKeyException e) {

            logger.error(e);
        }


        return aes.getAlgorithm();


    }

    public static void demoSymmetricAES() throws ParseException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException {


        logger.info("====================================.");
        logger.info("Begin executing method demoSymmetricAES.");

        int keyLength = 128;
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyLength);
        SecretKey secretKey = keyGen.generateKey();

        Cipher aes = Cipher.getInstance("AES");
        aes.init(Cipher.ENCRYPT_MODE, secretKey);
        String passphrase = "my passphrase is better than yours";

        logger.info("passphrase: " + passphrase);
        logger.info("cipher: " + aes.getAlgorithm());
        logger.info("keyLength: " + keyLength);
        logger.info("the key: " + secretKey.getEncoded());

        byte[] byteDataToEncrypt = passphrase.getBytes();
        byte[] ciphertext = aes.doFinal(byteDataToEncrypt);

        logger.info("generated ciphertext from aes algorythim: " + ciphertext.toString());

        aes.init(Cipher.DECRYPT_MODE, secretKey, aes.getParameters());
        String cleartext = new String(aes.doFinal(ciphertext));

        logger.info("Password in clear text: " + cleartext);

    }

    public static String getFirstProviderName() {

        Provider[] providers = Security.getProviders();

        return providers[0].getName();
    }

    public static void getProviderList() {
        logger.info("====================================.");
        logger.info("Generating list of security providers:");

        Provider[] providers = Security.getProviders();

        for (Provider prov : providers) {
            logger.info("provider name: " + prov.getName());
        }

    }

    public static void SHAHash() throws NoSuchAlgorithmException {

        //String myEncryptedPwd = "sLWjmMojKLJpX24ry9F8Fg==";//footbb78

        logger.info("====================================.");
        logger.info("Begin executing method SHAHash.");

        String myEncryptedPwd = "iWQkNoiW1aJyymGN4KTS9A==";  //footbb77

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        logger.info("message digest: " + md.getAlgorithm());

        md.update(myEncryptedPwd.getBytes());

        //byte[] byteData = md.digest();
        byte[] byteData = myEncryptedPwd.getBytes();

        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        logger.info("Hex format : " + hexString.toString());
        logger.info("Hash length: " + hexString.toString().length());

    }

    public static void demoRSAAlgorithm() {

        try {
            Cipher rsa = javax.crypto.Cipher.getInstance("RSA/NONE/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            logger.error(e);
        } catch (NoSuchPaddingException e) {
            logger.error(e);
        }

        String BadipAddress = "10.23.54.100";

    }

    public static String stripXSS(String value) {
        if (value != null) {
            // NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
            // avoid encoded attacks.
            logger.info("====================================.");
            logger.info("Begin XSS strip.");


            logger.info("XSS before encode: " + value);
            value = ESAPI.encoder().canonicalize(value);
            logger.info("XSS before: " + value);

            // Avoid null characters
            value = value.replaceAll("\0", "");

            // Remove all sections that match a pattern
            for (Pattern scriptPattern : patterns){
                value = scriptPattern.matcher(value).replaceAll("");
                logger.info("pattern: " + scriptPattern);
            }

            logger.info("XSS after: " + value);
        }
        return value;
    }

    public static void doESAPIValidations() {

        logger.info("====================================.");
        logger.info("Begin ESAPI Validation.");

        Validator validator = ESAPI.validator();

        StringBuilder sb = new StringBuilder();
        sb.append(System.getProperty("line.separator"));
        sb.append("Is valid credit card: ");
        sb.append(validator.isValidCreditCard("myCC", "1111222233334444", false));
        sb.append(System.getProperty("line.separator"));
        sb.append("Is valid date: ");
        DateFormat df = DateFormat.getDateInstance(DateFormat.LONG, Locale.US);
        sb.append(validator.isValidDate( "myDate", "January 20, 1967", df, false));

        logger.info(sb.toString());

    }

    public static void doESAPIEncryption () {

        logger.info("====================================.");
        logger.info("Begin ESAPI Encryption.");

        Encryptor encryptor = ESAPI.encryptor();
        PlainText pt = new PlainText("helloworld");
        try {

            logger.info("plaintext: " + pt);
            CipherText cipher = encryptor.encrypt(pt);
            logger.info("algorithm: " + cipher.getCipherAlgorithm());
            logger.info("cipher mode: " + cipher.getCipherMode());
            logger.info("raw cipher text: " + cipher.getRawCipherText());


        } catch (EncryptionException e) {
            e.printStackTrace();
        }


    }

    public static void preloadESAPI() {

        logger.info("====================================.");
        logger.info("Begin Preload.");

        Encryptor encryptor = ESAPI.encryptor();


    }
}
