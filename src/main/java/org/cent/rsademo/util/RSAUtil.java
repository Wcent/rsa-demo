package org.cent.rsademo.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * RSA工具类应用示例
 * 可用于生成公私密钥对，base64编码字符串
 * 公钥加密/私钥解密数据，私钥加密/公钥解密数据，RSA算法有限制最大长度，超长则需要分块加密解密，未实现
 * 私钥加签，公钥解签/验签
 * 生成数字摘要的base64编码字符串
 * @author cent
 * @version 1.0 2019-06-09
 */
public class RSAUtil {
    // 生成公私密钥对大小
    private static final int KEY_SIZE = 1024;
    // 生成公私密钥对算法类型，用于加密/解密算法类型
    private static final String KEY_ALG_TYPE = "RSA";
    // 生成签名算法类型，加签/验签算法类型
    private static final String SIGN_ALG_TYPE = "MD5withRSA";
//    private static final String SIGN_ALG_TYPE = "SHA256withRSA";

    /**
     * 生成base64编码密钥对
     * @return 密钥对map, uk对应publicKey， rk对应privateKey
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, String> genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALG_TYPE);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Map<String, String> keyPairMap = new HashMap<String, String>();
        keyPairMap.put("uk", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        keyPairMap.put("rk", Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        return keyPairMap;
    }

    /**
     * 公钥的base64字符串转换公钥
     * @param key 公钥的base64编码字符串
     * @return 公钥实例
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance(KEY_ALG_TYPE).generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * 私钥的base64字符串转换私钥
     * @param key 私钥的base64编码字符串
     * @return 私钥实例
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance(KEY_ALG_TYPE).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    /**
     * 公钥加密数据
     * @param key 公钥的base64编码字符串
     * @param data 待加密数据，明文字符串
     * @return 加密后数据的base64编码字符串
     */
    public static String encryptByPublicKey(String key, String data) {
        try {
            PublicKey publicKey = getPublicKey(key);
            Cipher cipher = Cipher.getInstance(KEY_ALG_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥解密数据
     * @param key 私钥的base64编码字符串
     * @param data 待解密数据，公钥加密后数据的base64编码字符串
     * @return 解密得到的数据，明文
     */
    public static String decryptByPrivateKey(String key, String data) {
        try {
            PrivateKey privateKey = getPrivateKey(key);
            Cipher cipher = Cipher.getInstance(KEY_ALG_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(data)), UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥加密数据
     * @param key 私钥的base64编码字符串
     * @param data 待加密数据，明文字符串
     * @return 加密后数据的base64编码字符串
     */
    public static String encryptByPrivateKey(String key, String data) {
        try {
            PrivateKey privateKey = getPrivateKey(key);
            Cipher cipher = Cipher.getInstance(KEY_ALG_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥解密数据
     * @param key 公钥的base64编码字符串
     * @param data 待解密数据，私钥加密后数据的base64编码字符串
     * @return 解密得到的数据，明文
     */
    public static String decryptByPublicKey(String key, String data) {
        try {
            PublicKey publicKey = getPublicKey(key);
            Cipher cipher = Cipher.getInstance(KEY_ALG_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(data)), UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥对数据加签，生成签名
     * @param key 私钥的base64编码字符串
     * @param data 待加签数据，明文
     * @return 数据签名的base64字符串
     */
    public static String sign(String key, String data) {
        try {
            PrivateKey privateKey = getPrivateKey(key);
            Signature signature = Signature.getInstance(SIGN_ALG_TYPE);
            signature.initSign(privateKey);
            signature.update(data.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥对数据验签，公钥解密签名比对数据是否一致
     * @param key 公钥的base64编码字符串
     * @param data 待验签数据，明文
     * @param sign 数据目标签名，私钥对数据加签生成的签名
     * @return 是否验签通过
     */
    public static boolean verify(String key, String data, String sign) {
        try {
            PublicKey publicKey = getPublicKey(key);
            Signature signature = Signature.getInstance(SIGN_ALG_TYPE);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(UTF_8));
            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 根据算法类型生成数据的数字摘要
     * @param data 数据
     * @param algorithm 算法类型，MD2/MD5/SHA-1/SHA-256/SHA-384/SHA-512
     * @return 数字摘要的base64字符串
     */
    public static String messageDigest(String data, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(data.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}

