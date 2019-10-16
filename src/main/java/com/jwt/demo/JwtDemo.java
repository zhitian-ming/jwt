package com.jwt.demo;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

public class JwtDemo {

    private static final Map<String, String> sigAlgs = new HashMap<String, String>();

    public static void main(String[] args) {
        //密钥库文件
        String keystore = "xc.keystore";
        //密钥库密码
        String keystore_password = "xuechengkeystore";

        //密钥别名
        String alias = "xckey";
        //密钥访问密码
        String key_password = "xuecheng";


        try {
            KeyStore keyStore = KeyStore.getInstance("jks");
            InputStream inputStream = JwtDemo.class.getClassLoader().getResourceAsStream("xc.keystore");
            keyStore.load(inputStream, keystore_password.toCharArray());
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey(alias, key_password.toCharArray());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            KeyPair keyPair = new KeyPair(publicKey, key);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            Map<String, Object> headerMap = new HashMap<String, Object>();
            headerMap.put("alg", sigAlgs.get("SHA256withRSA"));
            headerMap.put("typ", "JWT");
            Jwts.builder().setHeader(headerMap);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    static {
        sigAlgs.put("HMACSHA256", "HS256");
        sigAlgs.put("HMACSHA384", "HS384");
        sigAlgs.put("HMACSHA512", "HS512");
        sigAlgs.put("SHA256withRSA", "RS256");
        sigAlgs.put("SHA512withRSA", "RS512");
        sigAlgs.put("RSA/ECB/PKCS1Padding", "RSA1_5");
    }

}
