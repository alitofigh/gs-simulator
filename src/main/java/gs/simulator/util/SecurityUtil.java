package gs.simulator.util;

import gs.simulator.exception.GsSecurityException;
import org.apache.commons.codec.binary.Base64;
import org.jpos.iso.ISOMsg;
import org.jpos.iso.ISOUtil;
import org.jpos.iso.packager.ISO87BPackager;
import org.jpos.iso.packager.ISO93BPackager;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static gs.simulator.exception.GsSecurityException.EXPECTED_KEY_NOT_FOUND_IN_KEY_STORE;


/**
 * @author Reza Shojaee, 12/18/12 3:52 PM
 */
public abstract class SecurityUtil {
    public static final String DES_ALGORITHM_NAME = "DES";
    public static final String DESEDE_ALGORITHM_NAME = "DESede";
    public static final String AES_ALGORITHM_NAME = "AES";
    public static final String RSA_ALGORITHM_NAME = "RSA";
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    public static final String DEFAULT_PKI_ALGORITHM = "SunX509";
    public static final String AES_WRAP_ALGORITHM_NAME = "AESWRAP";
    public static final String CBC_ALGORITHM_MODE = "CBC";
    // ECB is default mode in sun jce provider for des, 3des and blowfish,
    // though spec states it is provider-defined
    public static final String ECB_ALGORITHM_MODE = "ECB";
    // default padding mode in sun jce provider for des, 3des and blowfish,
    // Generally this should be PKCS7Padding for block sizes other than 8
    // (in .net it is known as PKCS7Padding)
    public static final String PKCS5_PADDING_MODE = "PKCS5Padding";
    public static final String PKCS1_PADDING_MODE = "PKCS1Padding";
    public static final String NO_PADDING_MODE = "NoPadding";
    public static final String ZERO_PADDING_MODE = "ZeroPadding";
    public static final String SHA_256_ALGORITHM_NAME = "SHA-256";
    public static final String SHA1_ALGORITHM_NAME = "SHA1";
    public static final String MD5_ALGORITHM_NAME = "MD5";
    public static final String DES_CBC_NO_PADDING_SPEC =
            DES_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + NO_PADDING_MODE;
    public static final String DES_ECB_NO_PADDING_SPEC =
            DES_ALGORITHM_NAME + "/" + ECB_ALGORITHM_MODE
                    + "/" + NO_PADDING_MODE;
    public static final String DES_CBC_ZERO_PADDING_SPEC =
            DES_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + ZERO_PADDING_MODE;
    public static final String DESEDE_CBC_NO_PADDING_SPEC =
            DESEDE_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + NO_PADDING_MODE;
    public static final String DESEDE_ECB_NO_PADDING_SPEC =
            DESEDE_ALGORITHM_NAME + "/" + ECB_ALGORITHM_MODE
                    + "/" + NO_PADDING_MODE;
    public static final String DES_CBC_PKCS5_PADDING_SPEC =
            DES_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + PKCS5_PADDING_MODE;
    public static final String DESEDE_ECB_PKCS5_PADDING_SPEC =
            DESEDE_ALGORITHM_NAME + "/" + ECB_ALGORITHM_MODE
                    + "/" + PKCS5_PADDING_MODE;
    public static final String DESEDE_CBC_PKCS5_PADDING_SPEC =
            DESEDE_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + PKCS5_PADDING_MODE;
    public static final String AES_CBC_PKCS5_PADDING_SPEC =
            AES_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + PKCS5_PADDING_MODE;
    public static final String AES_CBC_NO_PADDING_SPEC =
            AES_ALGORITHM_NAME + "/" + CBC_ALGORITHM_MODE
                    + "/" + NO_PADDING_MODE;
    public static final String RSA_ECB_PKCS1_PADDING_SPEC =
            RSA_ALGORITHM_NAME + "/" + ECB_ALGORITHM_MODE
                    + "/" + PKCS1_PADDING_MODE;
    public static final int DES_KEY_SIZE = 8;
    public static final int DESEDE_DOUBLE_KEY_SIZE = 16;
    public static final int DESEDE_TRIPLE_KEY_SIZE = 24;
    public static final byte[] ALL_ZEROS_8_BYTE_BLOCK =
            new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
    public static final byte[] ALL_ZEROS_16_BYTE_BLOCK =
            new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    public static final byte[] ALL_ONES_8_BYTE_BLOCK =
            new byte[]{ /*0x11*/17, 17, 17, 17, 17, 17, 17, 17};
    public static final int PBKDF2_ITERATION_COUNT = 1000;
    public static final int PBKDF2_HASH_SIZE = 24 * 8;  // in bits
    public static final int PBKDF2_SALT_SIZE = 24;  // in bytes

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final String FIXED_PREDEFINED_SECRET = "pr0PerT5./~!@#$%";
    public static final String FIXED_PREDEFINED_IV = "`1qaz@WS";
    public static final String DEFAULT_ENCODING = "UTF-8";
    public static final String UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE =
            "Unsupported algorithm (cannot generate associated secret key)!";

    public static byte[] encrypt(
            byte[] plainData, int offset, int length, byte[] key,
            String algorithmSpec, byte[] initializationVector)
            throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpec.length() < 3)
            throw new NoSuchAlgorithmException(
                    "Malformed algorithm spec; it should specify 3 parts");
        SecretKeyFactory secretKeyFactory = null;
        if (!AES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0]))
            secretKeyFactory =
                    SecretKeyFactory.getInstance(algorithmSpecParts[0]);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0])) {
            assert secretKeyFactory != null;
            secretKey = secretKeyFactory.generateSecret(new DESKeySpec(key));
        } else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0])) {
            if (key.length < 16)
                throw new InvalidKeyException(
                        "Wrong key size for DESede algorithm: " + key.length);
            if (key.length < DESEDE_TRIPLE_KEY_SIZE) {
                byte[] adjustedKeyBytes = new byte[DESEDE_TRIPLE_KEY_SIZE];
                System.arraycopy(key, 0, adjustedKeyBytes,
                        0, DESEDE_DOUBLE_KEY_SIZE);
                System.arraycopy(key, 0, adjustedKeyBytes,
                        key.length, DES_KEY_SIZE);
                key = adjustedKeyBytes;
            }
            assert secretKeyFactory != null;
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(key));
        } else if (AES_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0])) {
            secretKey = new SecretKeySpec(key, AES_ALGORITHM_NAME);
        } else
            throw new Exception(UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        IvParameterSpec ivParameterSpec = null;
        if (!ECB_ALGORITHM_MODE.equals(algorithmSpecParts[1])) {
            byte[] ivBytes;
            if (initializationVector != null) {
                ivBytes = initializationVector;
            } else {
                if (AES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0]))
                    ivBytes = ALL_ZEROS_16_BYTE_BLOCK;
                else
                    ivBytes = ALL_ZEROS_8_BYTE_BLOCK;
            }
            ivParameterSpec = new IvParameterSpec(ivBytes);
        }
        Cipher encryptor = Cipher.getInstance(algorithmSpec);
        encryptor.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return encryptor.doFinal(plainData, offset, length);
    }

    public static byte[] decrypt(
            byte[] encryptedData, int offset, int length, byte[] key,
            String algorithmSpec, byte[] initializationVector)
            throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpec.length() < 3)
            throw new NoSuchAlgorithmException(
                    "Malformed algorithm spec; it should specify 3 parts");
        SecretKeyFactory secretKeyFactory = null;
        if (!AES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0]))
            secretKeyFactory =
                    SecretKeyFactory.getInstance(algorithmSpecParts[0]);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0])) {
            assert secretKeyFactory != null;
            secretKey = secretKeyFactory.generateSecret(new DESKeySpec(key));
        } else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0])) {
            if (key.length < 16)
                throw new InvalidKeyException(
                        "Wrong key size for DESede algorithm: " + key.length);
            if (key.length < DESEDE_TRIPLE_KEY_SIZE) {
                byte[] adjustedKeyBytes = new byte[DESEDE_TRIPLE_KEY_SIZE];
                System.arraycopy(key, 0, adjustedKeyBytes,
                        0, DESEDE_DOUBLE_KEY_SIZE);
                System.arraycopy(key, 0, adjustedKeyBytes,
                        key.length, DES_KEY_SIZE);
                key = adjustedKeyBytes;
            }
            assert secretKeyFactory != null;
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(key));
        } else if (AES_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0])) {
            secretKey = new SecretKeySpec(key, AES_ALGORITHM_NAME);
        } else
            throw new Exception(UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        IvParameterSpec ivParameterSpec = null;
        if (!ECB_ALGORITHM_MODE.equals(algorithmSpecParts[1])) {
            byte[] ivBytes;
            if (initializationVector != null) {
                ivBytes = initializationVector;
            } else {
                if (AES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0]))
                    ivBytes = ALL_ZEROS_16_BYTE_BLOCK;
                else
                    ivBytes = ALL_ZEROS_8_BYTE_BLOCK;
            }
            ivParameterSpec = new IvParameterSpec(ivBytes);
        }
        Cipher decryptor = Cipher.getInstance(algorithmSpec);
        decryptor.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return decryptor.doFinal(encryptedData, offset, length);
    }

    public static byte[] encryptRsa(
            byte[] plainData, int offset, int length, Key key,
            String algorithmSpec) throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpecParts.length < 3)
            throw new NoSuchAlgorithmException();
        Cipher cipher = Cipher.getInstance(algorithmSpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainData, offset, length);
    }

    public static byte[] decryptRsa(
            byte[] encryptedData, int offset, int length, Key key,
            String algorithmSpec) throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpecParts.length < 3)
            throw new NoSuchAlgorithmException();
        Cipher cipher = Cipher.getInstance(algorithmSpec);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData, offset, length);
    }

    // TODO include offset and length parameters to method and provide an
    // overload one
    public static byte[] hash(byte[] data, String algorithmName)
            throws Exception {
        MessageDigest messageDigest =
                MessageDigest.getInstance(algorithmName);
        return messageDigest.digest(data);
    }

    public static byte[] wrapKey(
            byte[] keyBytes, byte[] masterKeyBytes, String algorithm)
            throws Exception {
        if (AES_ALGORITHM_NAME.equalsIgnoreCase(algorithm)
                && DES_ALGORITHM_NAME.equalsIgnoreCase(algorithm))
            throw new GsSecurityException("Unsupported key algorithm");
        Key rootKey = new SecretKeySpec(masterKeyBytes, AES_ALGORITHM_NAME);
        Key keyToWrap = new SecretKeySpec(keyBytes, algorithm);
        Cipher cipher = Cipher.getInstance(AES_WRAP_ALGORITHM_NAME);
        cipher.init(Cipher.WRAP_MODE, rootKey);
        return cipher.wrap(keyToWrap);
    }

    public static byte[] unwrapKey(
            byte[] wrappedKeyBytes, byte[] masterKeyBytes, String algorithm)
            throws Exception {
        if (AES_ALGORITHM_NAME.equalsIgnoreCase(algorithm)
                && DES_ALGORITHM_NAME.equalsIgnoreCase(algorithm))
            throw new GsSecurityException("Unsupported key algorithm");
        Key rootKey = new SecretKeySpec(masterKeyBytes, AES_ALGORITHM_NAME);
        Cipher cipher = Cipher.getInstance(AES_WRAP_ALGORITHM_NAME);
        cipher.init(Cipher.UNWRAP_MODE, rootKey);
        return cipher.unwrap(
                wrappedKeyBytes, algorithm, Cipher.SECRET_KEY).getEncoded();
    }

    public byte[] deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
                password, salt, PBKDF2_ITERATION_COUNT, PBKDF2_HASH_SIZE);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }

    public byte[][] deriveKey(char[] password)
            throws Exception {
        byte[] salt = new byte[PBKDF2_SALT_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        byte[][] deriveKeyData = new byte[2][];
        deriveKeyData[0] = deriveKey(password, salt);
        deriveKeyData[1] = salt;
        return deriveKeyData;
    }

    public static KeyStore loadKeyStore(String storePath, char[] password)
            throws Exception {
        KeyStore keyStore;
        try (FileInputStream keyStoreInputStream =
                     new FileInputStream(storePath)) {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreInputStream, password);
        }
        return keyStore;
    }

    // Key password is considered the same as store password
    public static KeyManagerFactory getKeyManagerFactory(
            String storePath, char[] password) throws Exception {
        String algorithm =
                Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null)
            algorithm = DEFAULT_PKI_ALGORITHM;
        KeyStore keyStore = loadKeyStore(storePath, password);
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(algorithm);
        keyManagerFactory.init(keyStore, password);
        return keyManagerFactory;
    }

    public static TrustManagerFactory getTrustManagerFactory(
            String storePath, char[] password) throws Exception {
        String algorithm =
                Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null)
            algorithm = DEFAULT_PKI_ALGORITHM;
        KeyStore keyStore = loadKeyStore(storePath, password);
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(algorithm);
        trustManagerFactory.init(keyStore);
        return trustManagerFactory;
    }

    public static byte[] encrypt(
            byte[] plainData, byte[] keyBytes, String algorithmSpec,
            byte[] initializationVectorBytes) throws Exception {
        return encrypt(plainData, 0, plainData.length,
                keyBytes, algorithmSpec, initializationVectorBytes);
    }

    public static byte[] encryptRsa(
            byte[] plainData, Key key, String algorithmSpec)
            throws Exception {
        return encryptRsa(plainData, 0, plainData.length, key, algorithmSpec);
    }

    public static byte[] encryptRsa(byte[] plainData, Key key)
            throws Exception {
        return encryptRsa(plainData, 0, plainData.length,
                key, RSA_ECB_PKCS1_PADDING_SPEC);
    }

    public static String encryptLicenseItem(
            String plainKey, String storePath, char[] password)
            throws Exception {
        Key key = extractPrivateKey(storePath, password, "license-issuer");
        if (key == null)
            throw new GsSecurityException(String.format(
                    EXPECTED_KEY_NOT_FOUND_IN_KEY_STORE,
                    "license-issuer", storePath));
        byte[] encryptedKey =
                encryptRsa(plainKey.getBytes(DEFAULT_ENCODING), key,
                        RSA_ECB_PKCS1_PADDING_SPEC);
        return java.util.Base64.getEncoder().encodeToString(encryptedKey);
    }

    public static byte[] decryptRsa(
            byte[] encryptedData, Key key, String algorithmSpec)
            throws Exception {
        return decryptRsa(
                encryptedData, 0, encryptedData.length, key, algorithmSpec);
    }

    public static byte[] decryptRsa(byte[] encryptedData, Key key)
            throws Exception {
        return decryptRsa(encryptedData, 0, encryptedData.length,
                key, RSA_ECB_PKCS1_PADDING_SPEC);
    }

    public static String decryptLicenseItem(
            String base64EncryptedKey, String storePath, char[] password)
            throws Exception {
        byte[] encryptedKey =
                java.util.Base64.getDecoder().decode(base64EncryptedKey);
        Certificate certificate =
                extractCertificate(storePath, password, "license-verifier");
        if (certificate == null)
            throw new GsSecurityException(String.format(
                    EXPECTED_KEY_NOT_FOUND_IN_KEY_STORE,
                    "license-verifier", storePath));
        return new String(decryptRsa(encryptedKey, certificate.getPublicKey(),
                RSA_ECB_PKCS1_PADDING_SPEC), DEFAULT_ENCODING);
    }

    public static byte[] decrypt(
            byte[] encryptedData, byte[] key, String algorithmSpec,
            byte[] initializationVector)
            throws Exception {
        return decrypt(encryptedData, 0, encryptedData.length,
                key, algorithmSpec, initializationVector);
    }

    public static byte[] hashSha1(byte[] data) throws Exception {
        return hash(data, SHA1_ALGORITHM_NAME);
    }

    public static byte[] hashMd5(byte[] data) throws Exception {
        return hash(data, MD5_ALGORITHM_NAME);
    }

    public static String hashMd5(String data) throws Exception {
        return ISOUtil.hexString(hash(data.getBytes(), MD5_ALGORITHM_NAME));
    }

    // Key password is considered the same as store password
    public static Key extractPrivateKey(
            String storePath, char[] password, String keyAlias)
            throws Exception {
        KeyStore keyStore = loadKeyStore(storePath, password);
        return keyStore.getKey(keyAlias, password);
    }

    public static Certificate extractCertificate(
            String storePath, char[] password, String keyAlias)
            throws Exception {
        KeyStore keyStore = loadKeyStore(storePath, password);
        return keyStore.getCertificate(keyAlias);
    }

    public static byte[] computeGsMessageMac(ISOMsg message, String key) throws Exception {
        message.set(64, ALL_ZEROS_16_BYTE_BLOCK);
        byte[] messageDump = message.pack();
        return computeGsMessageMac(messageDump, key.getBytes());
    }

    public static byte[] computeGsMessageMac(
            byte[] messageDump, byte[] keyBytes) throws Exception {
        byte[] key1 = Arrays.copyOfRange(keyBytes, 0, 16);
        byte[] key2 = Arrays.copyOfRange(keyBytes, 16, 32);
        byte[] key3 = Arrays.copyOfRange(keyBytes, 32, 48);
        byte[] paddedDump = padIso9797Gs(messageDump, 0, messageDump.length - 16);
        byte[] encryptedMessageDump =
                encrypt(paddedDump, 0, paddedDump.length, key1,
                        AES_CBC_NO_PADDING_SPEC, null);
        byte[] macBytes = new byte[16];
        System.arraycopy(encryptedMessageDump,
                encryptedMessageDump.length - 16, macBytes, 0, 16);
        macBytes =
                decrypt(macBytes, key2, AES_CBC_NO_PADDING_SPEC, null);
        macBytes =
                encrypt(macBytes, key3, AES_CBC_NO_PADDING_SPEC, null);
        return macBytes;

    }

    public static byte[] padIso9797Gs(
            byte[] sourceBytes, int offset, int length) {
        int paddingLength = 16 - (length % 16 == 0 ? 16 : length % 16);
        byte[] zeroPaddedDump = Arrays.copyOfRange(
                sourceBytes, offset, length + paddingLength);
        // gotcha, last array elements (paddingLength) must be 0 which
        // currently have rawBytes values or you could originally create
        // a new array with appropriate length and use System.arraycopy()
        for (int i = zeroPaddedDump.length;
             i > zeroPaddedDump.length - paddingLength; i--)
            zeroPaddedDump[i - 1] = 0;
        return zeroPaddedDump;
    }

    public static byte[] computeAnsiX99Mac(
            byte[] messageDump, int offset, int length, byte[] keyBytes)
            throws Exception {
        byte[] paddedDump = padIso9797M1(messageDump, offset, length);
        byte[] encryptedMessageDump =
                encrypt(paddedDump, 0, paddedDump.length, keyBytes,
                        DES_CBC_NO_PADDING_SPEC, null);
        byte[] macBytes = new byte[8];
        System.arraycopy(encryptedMessageDump,
                encryptedMessageDump.length - 8, macBytes, 0, 8);
        return macBytes;
    }

    public static byte[] computeAnsiX99Mac(
            ISOMsg isoMessage, byte[] keyBytes)
            throws Exception {
        isoMessage.set(
                getResponseMacFieldNo(isoMessage), ALL_ZEROS_8_BYTE_BLOCK);
        byte[] messageDump = isoMessage.pack();
        int messageMacLength = getMacLength(isoMessage);
        return computeAnsiX99Mac(messageDump, 0,
                messageDump.length - messageMacLength, keyBytes);
    }

    public static byte[] computeAnsiX919Mac(
            byte[] messageDump, int offset, int length, byte[] keyBytes)
            throws Exception {
        byte[] key1 = Arrays.copyOfRange(keyBytes, 0, 8);
        byte[] key2 = Arrays.copyOfRange(keyBytes, 8, 16);
        byte[] stagedMacBytes =
                computeAnsiX99Mac(messageDump, offset, length, key1);
        stagedMacBytes =
                decrypt(stagedMacBytes, key2, DES_ECB_NO_PADDING_SPEC, null);
        stagedMacBytes =
                encrypt(stagedMacBytes, key1, DES_ECB_NO_PADDING_SPEC, null);
        return stagedMacBytes;
    }

    public static byte[] computeAnsiX919Mac(
            ISOMsg isoMessage, byte[] keyBytes)
            throws Exception {
        isoMessage.set(
                getResponseMacFieldNo(isoMessage), ALL_ZEROS_8_BYTE_BLOCK);
        byte[] messageDump = isoMessage.pack();
        int messageMacLength = getMacLength(isoMessage);
        return computeAnsiX919Mac(messageDump, 0,
                messageDump.length - messageMacLength, keyBytes);
    }

    public static byte[] encryptStreamZeroPad(
            InputStream inputStream, byte[] keyBytes, String algorithmSpec,
            byte[] initializationVectorBytes)
            throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpec.length() < 3)
            throw new NoSuchAlgorithmException();
        SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance(algorithmSpecParts[0]);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0]))
            secretKey = secretKeyFactory.generateSecret(
                    new DESKeySpec(keyBytes));
        else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0]))
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(keyBytes));
        else
            throw new Exception(UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        Cipher encryptor = Cipher.getInstance(algorithmSpec);
        IvParameterSpec ivParameterSpec = initializationVectorBytes != null
                ? new IvParameterSpec(initializationVectorBytes)
                : new IvParameterSpec(ALL_ZEROS_8_BYTE_BLOCK);
        encryptor.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainData = new byte[10000];
        int actualBytesCount = inputStream.read(plainData);
        inputStream.close();
        plainData = Arrays.copyOf(plainData, actualBytesCount);
        int paddingLength =
                8 - (plainData.length % 8 == 0 ? 8 : plainData.length % 8);
        byte[] finalPaddedDump =
                Arrays.copyOf(plainData, plainData.length + paddingLength);
        // gotcha, last array elements (paddingLength) must be 0 which
        // currently have rawBytes values or you could originally create a
        // new array with appropriate length and use System.arraycopy()
        for (int i = finalPaddedDump.length;
             i > finalPaddedDump.length - paddingLength; i--)
            finalPaddedDump[i - 1] = 0;
        return encryptor.doFinal(finalPaddedDump);
    }

    public static byte[] decryptStreamZeroUnpad(
            InputStream inputStream, byte[] keyBytes, String algorithmSpec,
            byte[] initializationVectorBytes)
            throws Exception {
        String[] algorithmSpecParts = algorithmSpec.split("/");
        if (algorithmSpec.length() < 3)
            throw new Exception("Malformed algorithm spec string, "
                    + "spec should contain at least 3 parts.");
        SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance(algorithmSpecParts[0]);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(algorithmSpecParts[0]))
            secretKey = secretKeyFactory.generateSecret(
                    new DESKeySpec(keyBytes));
        else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(
                algorithmSpecParts[0]))
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(keyBytes));
        else
            throw new Exception(UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        Cipher decryptor = Cipher.getInstance(algorithmSpec);
        IvParameterSpec ivParameterSpec = initializationVectorBytes != null
                ? new IvParameterSpec(initializationVectorBytes)
                : new IvParameterSpec(ALL_ZEROS_8_BYTE_BLOCK);
        decryptor.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedData = new byte[10000];
        int actualBytesCount = inputStream.read(encryptedData);
        inputStream.close();
        encryptedData = Arrays.copyOf(encryptedData, actualBytesCount);
        byte[] plainData = decryptor.doFinal(encryptedData);
        int unpaddedLen;
        for (unpaddedLen = plainData.length - 1;
             unpaddedLen >= 0; unpaddedLen--)
            if (plainData[unpaddedLen] != 0)
                break;
        return Arrays.copyOf(plainData, unpaddedLen + 1);
    }

    public static byte[] encryptWithKeyHashing(
            InputStream inputStream, byte[] keyBytes,
            String cipherAlgorithmName, String cipherAlgorithmMode,
            String cipherPaddingMode, String digestAlgorithmName,
            byte[] initializationVectorBytes, String textEncoding)
            throws Exception {
        SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance(cipherAlgorithmName);
        MessageDigest digest =
                MessageDigest.getInstance(digestAlgorithmName);
        keyBytes = Base64.encodeBase64String(
                digest.digest(keyBytes)).getBytes(textEncoding);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(cipherAlgorithmName))
            secretKey = secretKeyFactory.generateSecret(
                    new DESKeySpec(keyBytes));
        else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(
                cipherAlgorithmName))
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(keyBytes));
        else
            throw new Exception(UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        Cipher encryptor = Cipher.getInstance(
                cipherAlgorithmName + "/" + cipherAlgorithmMode
                        + "/" + cipherPaddingMode);
        IvParameterSpec ivParameterSpec = initializationVectorBytes != null
                ? new IvParameterSpec(initializationVectorBytes)
                : new IvParameterSpec(ALL_ZEROS_8_BYTE_BLOCK);
        encryptor.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainData = new byte[10000];
        int actualBytesCount = inputStream.read(plainData);
        actualBytesCount = actualBytesCount == -1 ? 0 : actualBytesCount;
        inputStream.close();
        plainData = Arrays.copyOf(plainData, actualBytesCount);
        int paddingLength =
                8 - (plainData.length % 8 == 0 ? 8 : plainData.length % 8);
        byte[] finalPaddedDump =
                Arrays.copyOf(plainData, plainData.length + paddingLength);
        // gotcha, last array elements (paddingLength) must be 0 which
        // currently have rawBytes values or you could originally create a
        // new array with appropriate length and use System.arraycopy()
        for (int i = finalPaddedDump.length;
             i > finalPaddedDump.length - paddingLength; i--)
            finalPaddedDump[i - 1] = 0;
        return Base64.encodeBase64(encryptor.doFinal(finalPaddedDump));
    }

    public static byte[] decryptWithKeyHashing(
            InputStream inputStream, byte[] keyBytes,
            String cipherAlgorithmName, String cipherAlgorithmMode,
            String cipherPaddingMode, String digestAlgorithmName,
            byte[] initializationVectorBytes, String textEncoding)
            throws NoSuchAlgorithmException, IOException,
            InvalidKeyException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            BadPaddingException, IllegalBlockSizeException {
        SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance(cipherAlgorithmName);
        MessageDigest digest =
                MessageDigest.getInstance(digestAlgorithmName);
        keyBytes = Base64.encodeBase64String(
                digest.digest(keyBytes)).getBytes(textEncoding);
        SecretKey secretKey;
        if (DES_ALGORITHM_NAME.equalsIgnoreCase(cipherAlgorithmName))
            secretKey = secretKeyFactory.generateSecret(
                    new DESKeySpec(keyBytes));
        else if (DESEDE_ALGORITHM_NAME.equalsIgnoreCase(cipherAlgorithmName))
            secretKey = secretKeyFactory.generateSecret(
                    new DESedeKeySpec(keyBytes));
        else
            throw new InvalidAlgorithmParameterException(
                    UNSUPPORTED_ALGORITHM_KEY_PAIR_MESSAGE);
        Cipher decryptor = Cipher.getInstance(
                cipherAlgorithmName + "/" + cipherAlgorithmMode
                        + "/" + cipherPaddingMode);
        IvParameterSpec ivParameterSpec = initializationVectorBytes != null
                ? new IvParameterSpec(initializationVectorBytes)
                : new IvParameterSpec(ALL_ZEROS_8_BYTE_BLOCK);
        decryptor.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encodedEncryptedData;
        encodedEncryptedData = new byte[10000];
        int actualBytesCount = inputStream.read(encodedEncryptedData);
        actualBytesCount = actualBytesCount == -1 ? 0 : actualBytesCount;
        inputStream.close();
        encodedEncryptedData =
                Arrays.copyOf(encodedEncryptedData, actualBytesCount);
        String encryptedData =
                new String(encodedEncryptedData, textEncoding);
        return decryptor.doFinal(Base64.decodeBase64(encryptedData));
    }

    public static String encryptMaskanDataItem(
            String dataItem, byte[] keyBytes)
            throws Exception {
        byte[] encryptedBytes = encrypt(dataItem.getBytes(), keyBytes,
                DES_CBC_PKCS5_PADDING_SPEC, null);
        return new String(
                Base64.encodeBase64(encryptedBytes), DEFAULT_ENCODING);
    }

    /**
     * @param dataItem plain data item to be encrypted, its encoding is
     *                 considered default
     * @param key      key string encoded in hexadecimal format, i.e. it
     *                 translates to a 8-byte key
     * @return encrypted data item represented in Base64 encoding
     * @throws Exception
     */
    public static String encryptMaskanDataItem(String dataItem, String key)
            throws Exception {
        return encryptMaskanDataItem(dataItem,
                ISOUtil.hex2byte(StringUtil.fixWidthZeroPad(key, 16)));
    }

    public static String encryptMaskanVoucher(
            String voucherPin, String voucherSerial)
            throws Exception {
        return encryptMaskanDataItem(voucherPin,
                StringUtil.fixWidthZeroPad(voucherSerial, 8).getBytes());
    }

    public static String decryptMaskanDataItem(
            String dataItem, byte[] keyBytes)
            throws Exception {
        byte[] plainBytes =
                decrypt(Base64.decodeBase64(dataItem.getBytes()),
                        keyBytes, DES_CBC_PKCS5_PADDING_SPEC, null);
        return new String(plainBytes, DEFAULT_ENCODING);
    }

    public static String decryptMaskanDataItem(String dataItem, String key)
            throws Exception {
        return decryptMaskanDataItem(dataItem,
                ISOUtil.hex2byte(StringUtil.fixWidthZeroPad(key, 16)));
    }

    public static String decryptMaskanVoucher(
            String voucherPin, String voucherSerial)
            throws Exception {
        return decryptMaskanDataItem(voucherPin,
                StringUtil.fixWidthZeroPad(voucherSerial, 8).getBytes());
    }

    public static String encryptCredentialAllParamsPredefined(
            String credential)
            throws Exception {
        return new String(encryptAllParamsPredefined(
                new ByteArrayInputStream(credential.getBytes())));
    }

    public static String decryptCredentialAllParamsPredefined(
            String credential)
            throws NoSuchPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, IOException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        return new String(decryptAllParamsPredefined(
                new ByteArrayInputStream(credential.getBytes())));
    }

    public static byte[] encryptAllParamsPredefined(InputStream inputStream)
            throws Exception {
        return encryptWithKeyHashing(
                inputStream,
                FIXED_PREDEFINED_SECRET.getBytes(DEFAULT_ENCODING),
                DESEDE_ALGORITHM_NAME, CBC_ALGORITHM_MODE,
                NO_PADDING_MODE, SHA_256_ALGORITHM_NAME,
                FIXED_PREDEFINED_IV.getBytes(DEFAULT_ENCODING),
                DEFAULT_ENCODING);
    }

    public static byte[] decryptAllParamsPredefined(InputStream inputStream)
            throws IOException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, InvalidKeySpecException {
        byte[] decryptedBytes = decryptWithKeyHashing(
                inputStream,
                FIXED_PREDEFINED_SECRET.getBytes(DEFAULT_ENCODING),
                DESEDE_ALGORITHM_NAME, CBC_ALGORITHM_MODE, NO_PADDING_MODE,
                SHA_256_ALGORITHM_NAME,
                FIXED_PREDEFINED_IV.getBytes(DEFAULT_ENCODING),
                DEFAULT_ENCODING);
        return makeUnpaddedCopy(decryptedBytes);
    }

    public static byte[] encryptInputStream(
            InputStream inputStream, String algorithmSpec, byte[] keyBytes)
            throws Exception {
        return encryptStreamZeroPad(
                inputStream, keyBytes, algorithmSpec, null);
    }

    public static byte[] decryptInputStream(
            InputStream inputStream, String algorithmSpec, byte[] keyBytes)
            throws Exception {
        return decryptStreamZeroUnpad(
                inputStream, keyBytes, algorithmSpec, null);
    }

    public static byte[] padIso9797M1(
            byte[] sourceBytes, int offset, int length) {
        int paddingLength = 8 - (length % 8 == 0 ? 8 : length % 8);
        byte[] zeroPaddedDump = Arrays.copyOfRange(
                sourceBytes, offset, length + paddingLength);
        // gotcha, last array elements (paddingLength) must be 0 which
        // currently have rawBytes values or you could originally create
        // a new array with appropriate length and use System.arraycopy()
        for (int i = zeroPaddedDump.length;
             i > zeroPaddedDump.length - paddingLength; i--)
            zeroPaddedDump[i - 1] = 0;
        return zeroPaddedDump;
    }

    public static byte[] makeZeroPaddedCopy(
            byte[] sourceBytes, int trailingLengthToExclude) {
        if ((sourceBytes.length - trailingLengthToExclude) % 8 == 0)
            return Arrays.copyOf(sourceBytes,
                    sourceBytes.length - trailingLengthToExclude);
        int paddingLength = 8 -
                (sourceBytes.length % 8 == 0 ? 8 : sourceBytes.length % 8);
        byte[] zeroPaddedDump =
                Arrays.copyOf(sourceBytes, sourceBytes.length
                        - trailingLengthToExclude + paddingLength);
        // gotcha, last array elements (paddingLength) must be 0 which
        // currently have rawBytes values or you could originally create a
        // new array with appropriate length and use System.arraycopy()
        for (int i = zeroPaddedDump.length;
             i > zeroPaddedDump.length - paddingLength; i--)
            zeroPaddedDump[i - 1] = 0;
        return zeroPaddedDump;
    }

    private static byte[] makeUnpaddedCopy(byte[] decryptedBytes) {
        int paddedZerosLength = 0;
        for (int i = decryptedBytes.length - 1; i >= 0; i--)
            if (decryptedBytes[i] == 0)
                paddedZerosLength++;
        return Arrays.copyOf(decryptedBytes,
                decryptedBytes.length - paddedZerosLength);
    }

    public static byte[] padPkcs5(byte[] unpaddedData)
            throws Exception {
        int paddingLength = 8 - unpaddedData.length % 8;
        byte[] paddedData = new byte[unpaddedData.length + paddingLength];
        System.arraycopy(unpaddedData, 0, paddedData,
                (short) 0, unpaddedData.length);
        for (int i = 0; i < paddingLength; i++)
            paddedData[unpaddedData.length + i] = (byte) paddingLength;
        return paddedData;
    }

    public static byte[] unpadPkcs5(byte[] paddedData)
            throws Exception {
        int paddingLength = paddedData[paddedData.length - 1];
        byte[] unpaddedData = new byte[paddedData.length - paddingLength];
        System.arraycopy(paddedData, 0, unpaddedData,
                (short) 0, paddedData.length - paddingLength);
        return unpaddedData;
    }

    public static byte[] padIso9797M1(byte[] data) {
        int paddingLength = 8 -
                (data.length % 8 == 0 ? 8 : data.length % 8);
        if (paddingLength == 0)
            return data;
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, (short) 0, data.length);
        for (int i = 0; i < paddingLength; i++)
            paddedData[data.length + i] = 0;
        return paddedData;
    }

    public static byte[] unpadIso9797M1(byte[] data) {
        int paddingLength = 0;
        for (int i = data.length - 1; i >= 0 && data[i] == 0; i--)
            paddingLength++;
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData,
                (short) 0, data.length - paddingLength);
        return unpaddedData;
    }

    public static byte[] computeAnsiX919MacDoAll(
            byte[] messageDump, int offset, int length, byte[] keyBytes)
            throws Exception {
        byte[] key1 = Arrays.copyOfRange(keyBytes, 0, 8);
        byte[] key2 = Arrays.copyOfRange(keyBytes, 8, 16);
        byte[] zeroPaddedDump =
                padIso9797M1(messageDump, offset, length);
        byte[] encryptedMessageDump =
                encrypt(zeroPaddedDump, 0, zeroPaddedDump.length,
                        key1, DES_CBC_NO_PADDING_SPEC, null);
        byte[] stagedMacBytes = new byte[8];
        System.arraycopy(encryptedMessageDump,
                encryptedMessageDump.length - 8, stagedMacBytes, 0, 8);
        stagedMacBytes = decrypt(
                stagedMacBytes, key2, DES_ECB_NO_PADDING_SPEC, null);
        stagedMacBytes = encrypt(
                stagedMacBytes, key1, DES_ECB_NO_PADDING_SPEC, null);
        return stagedMacBytes;
    }

    public static byte[] computeAnsiX919MacDoAll(
            ISOMsg isoMessage, byte[] keyBytes)
            throws Exception {
        int macFieldLength = getRequestMacFieldNo(isoMessage);
        byte[] messageDump = isoMessage.pack();
        return computeAnsiX919MacDoAll(messageDump, 0,
                messageDump.length - macFieldLength, keyBytes);
    }

    public static byte[] computeAnsiX919MacManualCbc(
            byte[] messageDump, int offset, int length, byte[] keyBytes)
            throws Exception {
        byte[] key1 = Arrays.copyOfRange(keyBytes, 0, 8);
        byte[] key2 = Arrays.copyOfRange(keyBytes, 8, 16);
        byte[] stagedMacBytes = computeAnsiX99MacManualCbc(
                messageDump, offset, length, key1, 0);
        stagedMacBytes = decrypt(stagedMacBytes, key2,
                DES_ECB_NO_PADDING_SPEC, null);
        stagedMacBytes = encrypt(stagedMacBytes, key1,
                DES_ECB_NO_PADDING_SPEC, null);
        return stagedMacBytes;
    }

    public static byte[] computeAnsiX919MacManualCbc(
            ISOMsg isoMessage, byte[] keyBytes)
            throws Exception {
        int macFieldLength = getMacLength(isoMessage);
        byte[] messageDump = isoMessage.pack();
        return computeAnsiX919MacManualCbc(messageDump, 0,
                messageDump.length - macFieldLength, keyBytes);
    }

    public static byte[] computeAnsiX99MacManualCbc(
            byte[] messageDump, int offset, int length,
            byte[] keyBytes, int trailingLengthToExclude)
            throws Exception {
        byte[] oneEncryptionBlock = new byte[8];
        byte[] stageResult = ALL_ZEROS_8_BYTE_BLOCK;
        int paddingLen = 8 - (length % 8 == 0 ? 8 : length % 8);
        byte[] paddedData =
                new byte[length - trailingLengthToExclude + paddingLen];
        System.arraycopy(messageDump, offset,
                paddedData, 0, length - trailingLengthToExclude);
        System.arraycopy(stageResult, 0,
                paddedData, length - trailingLengthToExclude, paddingLen);
        for (int i = 0; i < paddedData.length; i += 8) {
            System.arraycopy(paddedData, i, oneEncryptionBlock, 0, 8);
            // according to algorithm, at first step xor should not occur
            // but makes no difference to xor with all-zeros
            stageResult = ISOUtil.xor(stageResult, oneEncryptionBlock);
            // TODO do the whole thing here using update (to avoid calls
            // and making the same key over and over)
            stageResult = encrypt(
                    stageResult, keyBytes, DES_ECB_NO_PADDING_SPEC, null);
        }
        return stageResult;
    }

    public static byte[] computeAnsiX99MacManualCbc(
            ISOMsg isoMessage, byte[] keyBytes)
            throws Exception {
        int macFieldLength = getMacLength(isoMessage);
        byte[] messageDump = isoMessage.pack();
        return computeAnsiX99MacManualCbc(messageDump, 0,
                messageDump.length - macFieldLength, keyBytes, 0);
    }

    // Added these methods here to remove dependency to ProtocolRulesBase
    public static int getMacLength(ISOMsg isoMessage) {
        int macLength = 16;
        // TODO create @BinaryPackager and apply that on top of such
        // classes and find macLength based on this annotation
        if (isoMessage.getPackager() instanceof ISO87BPackager
                || isoMessage.getPackager() instanceof ISO93BPackager)
            macLength = 8;
        return macLength;
    }

    public static int getRequestMacFieldNo(ISOMsg isoMessage) {
        int macFieldNo = -1;
        /* NB! message received by acquirer may have maxField = 64 but
        outgoing message may have added fields beyond that, thus having
        max field greater than 64 and field 64 also being present in
        message means that original message had its mac set into field 64
        but newly added fields imply that outgoing message should have a new
        mac set into field 128, not having field 64 in original message
        in this case means no mac was present
        */
        //isoMessage.recalcBitMap();
        if (isoMessage.getMaxField() > 64) {
            // check whether any mac was been set into message at all
            if (isoMessage.hasField(128))
                macFieldNo = 128;
        } else {
            if (isoMessage.hasField(64))
                macFieldNo = 64;
        }
        return macFieldNo;
    }

    public static int getResponseMacFieldNo(ISOMsg isoMessage) {
        return isoMessage.getMaxField() > 64 ? 128 : 64;
    }
}
