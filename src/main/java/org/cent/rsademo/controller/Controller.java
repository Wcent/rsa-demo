package org.cent.rsademo.controller;

import com.alibaba.fastjson.JSONObject;
import org.cent.rsademo.util.RSAUtil;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

@RestController
public class Controller {

    @RequestMapping("/")
    public String sayHi() {
        return "Hello World!";
    }

    /**
     * 测试生成公私密钥对
     * @return 公私密钥对
     */
    @GetMapping("/genKeyPair")
    public Map<String, String> genKeyPair() {
        Map<String, String> keyPair = null;
        try {
            keyPair = RSAUtil.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * json post请求测试rsa非对称加密算法应用
     * 公钥加密/私钥解密，私钥加密/公钥解密，私钥加签/公钥验签
     * @param jsonObject 带公钥/私钥/数据的json参数
     * @return 测试后json结果
     */
    /* post json
    {
        "uk":"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzKsgr1ApXNa13aXbWMo2KxIG5Y8KyAC1MVCIExKLXq8AQKMvuf+o3N7RJhtkB7NrXYbgN+i/115d4rz7rAXJlFxZei1lvAb9YP31iSjH+c8JwbNfxIWp/TVzqfGL3VD7Za99MRpepWo5YTBAasz5WuUr3EckJgHiXDN6GcAlHjwIDAQAB",
        "rk":"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALMqyCvUClc1rXdpdtYyjYrEgbljwrIALUxUIgTEoterwBAoy+5/6jc3tEmG2QHs2tdhuA36L/XXl3ivPusBcmUXFl6LWW8Bv1g/fWJKMf5zwnBs1/Ehan9NXOp8YvdUPtlr30xGl6lajlhMEBqzPla5SvcRyQmAeJcM3oZwCUePAgMBAAECgYA/fkTLy2wStdIQhE554BZq+/Kg+WqQ3CExcItRt0GiPppk36BNmAUvpkz81Y3n8cEoHNg2E9iVPd7PBQO+EpgwBAkD+QJHdNpsut3hUbv4kspWFI/SrY9lNlUg7Ek2rlxU0g6uFwZftI77eXln3CJi+OMnm7fXM/Ed0r7LiAMmAQJBAPI95/9CCBo7LnFSCwjDcAJp6FggAS+9oYzq7K6iSCr1eLhUbnZ6qcc7u33h2cEZ2Sey4CaTYd+Xqh5+wR3q9I8CQQC9V8vOiz6SOYME48qDH5ZLIabE3F1F5e7I37JTzt7k0zl04mrZtXdK8NHRr+uA8t2VaBHRFMDRRn2JyTiTQ/0BAkEApe3Hqy401JrzLgYvrroIUG7xCuQpS+VN8nO82cYpPtvT7BdRbvCIuQLuY8S/Xqjw+WNqbKIJqZl+mtLiPzcAewJAO/jRDwy/tuUMgMH95OZeXlG8VuJNkNQxe+KOw0jlBKl6q3ED0w1NSalZbAdCmsdSM/6Qlh7yq9ad8MSRbOO+AQJAGcNjMAu+N6lJEPaW43m1zLaauyro49NVzj5gIRSU9rL0MN0Pn4LVHHCAlIMIjNA4b1N42GtVvNpLFYDVioA1bA==",
        "data":"hello world!"
    }
    */
    @PostMapping(value = "/rsa", produces = "application/json;charset=UTF-8")
    public JSONObject rsa(@RequestBody JSONObject jsonObject) {

        Map<String, String> map = new TreeMap<>();
        for (String key : jsonObject.keySet()) {
            String value = jsonObject.getObject(key, String.class);
            map.put(key, value);
        }

        String publicKey = jsonObject.getString("uk");
        String privateKey = jsonObject.getString("rk");
        String data = jsonObject.getString("data");

        // 公钥加密/私钥解密
        String encryptData = RSAUtil.encryptByPublicKey(publicKey, data);
        String decryptData = RSAUtil.decryptByPrivateKey(privateKey, encryptData);
        jsonObject.put("uk->rk", Boolean.toString(data.equals(decryptData)));
        jsonObject.put("encryptDataByPublicKey", encryptData);
        jsonObject.put("decryptDataByPrivateKey", decryptData);

        // 私钥加密/公钥解密
        encryptData = RSAUtil.encryptByPrivateKey(privateKey, data);
        decryptData = RSAUtil.decryptByPublicKey(publicKey, encryptData);
        jsonObject.put("rk->uk", Boolean.toString(data.equals(decryptData)));
        jsonObject.put("encryptDataByPrivateKey", encryptData);
        jsonObject.put("decryptDataByPublicKey", decryptData);

        // 模式私钥加签/公钥解签
        String signByPrivateKey = RSAUtil.encryptByPrivateKey(privateKey, data);
        String unsignData = RSAUtil.decryptByPublicKey(publicKey, signByPrivateKey);
        jsonObject.put("checkSign", Boolean.toString(data.equals(unsignData)));
        jsonObject.put("signByPrivateKey", signByPrivateKey);
        jsonObject.put("unsignData", unsignData);

        return jsonObject;
    }

    /**
     * json post请求测试接口数据加签应用
     * @param jsonObject 带公钥/私钥/数据的json参数
     * @return 测试后json结果
     */
    /* post json
    {
        "data": "hello world!",
        "uk": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzKsgr1ApXNa13aXbWMo2KxIG5Y8KyAC1MVCIExKLXq8AQKMvuf+o3N7RJhtkB7NrXYbgN+i/115d4rz7rAXJlFxZei1lvAb9YP31iSjH+c8JwbNfxIWp/TVzqfGL3VD7Za99MRpepWo5YTBAasz5WuUr3EckJgHiXDN6GcAlHjwIDAQAB",
        "rk": "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALMqyCvUClc1rXdpdtYyjYrEgbljwrIALUxUIgTEoterwBAoy+5/6jc3tEmG2QHs2tdhuA36L/XXl3ivPusBcmUXFl6LWW8Bv1g/fWJKMf5zwnBs1/Ehan9NXOp8YvdUPtlr30xGl6lajlhMEBqzPla5SvcRyQmAeJcM3oZwCUePAgMBAAECgYA/fkTLy2wStdIQhE554BZq+/Kg+WqQ3CExcItRt0GiPppk36BNmAUvpkz81Y3n8cEoHNg2E9iVPd7PBQO+EpgwBAkD+QJHdNpsut3hUbv4kspWFI/SrY9lNlUg7Ek2rlxU0g6uFwZftI77eXln3CJi+OMnm7fXM/Ed0r7LiAMmAQJBAPI95/9CCBo7LnFSCwjDcAJp6FggAS+9oYzq7K6iSCr1eLhUbnZ6qcc7u33h2cEZ2Sey4CaTYd+Xqh5+wR3q9I8CQQC9V8vOiz6SOYME48qDH5ZLIabE3F1F5e7I37JTzt7k0zl04mrZtXdK8NHRr+uA8t2VaBHRFMDRRn2JyTiTQ/0BAkEApe3Hqy401JrzLgYvrroIUG7xCuQpS+VN8nO82cYpPtvT7BdRbvCIuQLuY8S/Xqjw+WNqbKIJqZl+mtLiPzcAewJAO/jRDwy/tuUMgMH95OZeXlG8VuJNkNQxe+KOw0jlBKl6q3ED0w1NSalZbAdCmsdSM/6Qlh7yq9ad8MSRbOO+AQJAGcNjMAu+N6lJEPaW43m1zLaauyro49NVzj5gIRSU9rL0MN0Pn4LVHHCAlIMIjNA4b1N42GtVvNpLFYDVioA1bA=="
    }
    */
    @PostMapping(value = "/sign", produces = "application/json;charset=UTF-8")
    public JSONObject sign(@RequestBody JSONObject jsonObject) {

        Map<String, String> map = new TreeMap<>();
        for (String key : jsonObject.keySet()) {
            String value = jsonObject.getObject(key, String.class);
            map.put(key, value);
        }

        String privateKey = jsonObject.getString("rk");
        String sign = RSAUtil.sign(privateKey, map.toString());
        jsonObject.put("sign", sign);

        return jsonObject;
    }

    /**
     * json post请求测试接口数据解签应用
     * @param jsonObject 带公钥/私钥/数据/签名的json参数
     * @return 测试后json结果
     */
    /* post json
    {
        "data": "hello world!",
        "uk": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzKsgr1ApXNa13aXbWMo2KxIG5Y8KyAC1MVCIExKLXq8AQKMvuf+o3N7RJhtkB7NrXYbgN+i/115d4rz7rAXJlFxZei1lvAb9YP31iSjH+c8JwbNfxIWp/TVzqfGL3VD7Za99MRpepWo5YTBAasz5WuUr3EckJgHiXDN6GcAlHjwIDAQAB",
        "rk": "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALMqyCvUClc1rXdpdtYyjYrEgbljwrIALUxUIgTEoterwBAoy+5/6jc3tEmG2QHs2tdhuA36L/XXl3ivPusBcmUXFl6LWW8Bv1g/fWJKMf5zwnBs1/Ehan9NXOp8YvdUPtlr30xGl6lajlhMEBqzPla5SvcRyQmAeJcM3oZwCUePAgMBAAECgYA/fkTLy2wStdIQhE554BZq+/Kg+WqQ3CExcItRt0GiPppk36BNmAUvpkz81Y3n8cEoHNg2E9iVPd7PBQO+EpgwBAkD+QJHdNpsut3hUbv4kspWFI/SrY9lNlUg7Ek2rlxU0g6uFwZftI77eXln3CJi+OMnm7fXM/Ed0r7LiAMmAQJBAPI95/9CCBo7LnFSCwjDcAJp6FggAS+9oYzq7K6iSCr1eLhUbnZ6qcc7u33h2cEZ2Sey4CaTYd+Xqh5+wR3q9I8CQQC9V8vOiz6SOYME48qDH5ZLIabE3F1F5e7I37JTzt7k0zl04mrZtXdK8NHRr+uA8t2VaBHRFMDRRn2JyTiTQ/0BAkEApe3Hqy401JrzLgYvrroIUG7xCuQpS+VN8nO82cYpPtvT7BdRbvCIuQLuY8S/Xqjw+WNqbKIJqZl+mtLiPzcAewJAO/jRDwy/tuUMgMH95OZeXlG8VuJNkNQxe+KOw0jlBKl6q3ED0w1NSalZbAdCmsdSM/6Qlh7yq9ad8MSRbOO+AQJAGcNjMAu+N6lJEPaW43m1zLaauyro49NVzj5gIRSU9rL0MN0Pn4LVHHCAlIMIjNA4b1N42GtVvNpLFYDVioA1bA==",
        "sign": "e2xkBToLsXPb56vNodqSbF0iFik9fX74cdkHkNw2bxCf8dQzOku6HSIeowFIyTCkC5mRwUqkGzJjQpmE+NNXCltctIteajenpDPFE9gs2j3p6xIWkMOr3AEAIPbofxgVyOIC47sYTAhHAfm1oSQj4aOntRQ9fNff3UdR+zwy4vc="
    }
    */
    @PostMapping(value = "/verify", produces = "application/json;charset=UTF-8")
    public JSONObject verify(@RequestBody JSONObject jsonObject) {

        String sign = null;
        Map<String, String> map = new TreeMap<>();
        for (String key : jsonObject.keySet()) {
            String value = jsonObject.getObject(key, String.class);
            if (key.equals("sign"))
                sign = value;
            else
                map.put(key, value);
        }

        String publicKey = jsonObject.getString("uk");
        jsonObject.put("verify", Boolean.toString(RSAUtil.verify(publicKey, map.toString(), sign)));

        return jsonObject;
    }
}
