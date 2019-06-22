package org.cent.rsademo.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 密钥哈希认证工具
 * @author Vincent
 * @version 1.0 2019/6/22
 */
public class HmacUtil {

    public static final String HMACSHA256 = "HmacSHA256";
    public static final String HMACSHA512 = "HmacSHA512";

    /**
     * 约定密钥生成消息认证码（加签）
     * @param secretKey 约定密钥base64字符串
     * @param algorithm 摘要算法类型，HmacSHA256/HmacSHA512等
     * @param data 待加签消息
     * @return 消息签名的base64字符串
     */
    public static String hmac(String secretKey, String algorithm, String data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
