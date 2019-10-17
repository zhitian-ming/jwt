package com.jwt.demo;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtDemo {

    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", 32);
    private static volatile KeyStore keyStore;

    @Test
    public void createJwt() {
        //密钥库文件
        String keystore = "yj.keystore";
        //密钥库密码
        String keystorePassword = "yjpass";

        //密钥别名
        String alias = "yjkey";
        //密钥访问密码
        String keyPassword = "yjpass";

        RSAPrivateKey privateKey = getRsaPrivateKey(keystore, keystorePassword, alias, keyPassword);
        Map<String, Object> headerMap = new HashMap<String, Object>();
        headerMap.put("alg", SignatureAlgorithm.RS256);
        headerMap.put("typ", "JWT");
        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put("name", "zhangsan");
        payload.put("userId", 32145);

        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(currentDate.getTime() + 20000));
        Date expTime = calendar.getTime();
        String compact = Jwts.builder().setHeader(headerMap).setClaims(payload).setIssuedAt(currentDate).setExpiration(expTime)
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();
        System.out.println(compact);
    }

    @Test
    public void decode() {

        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiemhhbmdzYW4iLCJleHAiOjE1NzEyODM2ODQsInVzZXJJZCI6MzIxNDUsImlhdCI6MTU3MTI4MzY2NH0.ImmHA1uRfU1c3VONcQuVe3nbOmjPlnxupRALqIEH6l5u3YU3UumiAjKk8XWIyumkNved1kO3TLcC8SZli8IQ12FuxIFSoAzt9ZOCSsJyMqEY9r6KglUi8K8G8PMjKcecIBMBMHiYGjnq-H7Veo3hWQUxfQWvTh4iAjyM9aybBCvUzfXGQXeyAC7Wb200gqcSpajk9NPRuf2kb71R-WHGnIFwvX8_GQb7CwtJZOHTsjNyAXMrHq6wsXxQInmjynmFgC_IpCSc2YEh93mGfRqMQPViNGHJZQS7EOujjR19HoOEcj_Q92IuxZfrIMf2EpsxqiSz_H6uTQVZu5_KV7asmQ";

        RSAPublicKey key = getPublicKey("publickey.txt");

        Jwt jwt = Jwts.parser().setSigningKey(key).parse(token);
        Map body = (Map)jwt.getBody();
        Header header = jwt.getHeader();
        System.out.println(header);
        System.out.println(body);
    }

    private RSAPrivateKey getRsaPrivateKey(String keystore, String keystorePassword, String alias, String keyPassword) {
        try {
            if (keyStore == null) {
                synchronized (JwtDemo.class) {
                    if (keyStore == null) {
                        keyStore = KeyStore.getInstance("jks");
                        InputStream inputStream = JwtDemo.class.getClassLoader().getResourceAsStream(keystore);
                        keyStore.load(inputStream, keystorePassword.toCharArray());
                    }
                }
            }
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey(alias, keyPassword.toCharArray());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            KeyPair keyPair = new KeyPair(publicKey, key);
            return (RSAPrivateKey) keyPair.getPrivate();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private RSAPublicKey getPublicKey(String keyFile) {
        Matcher m = PEM_DATA.matcher(getKeyString(keyFile).trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        } else {
            String type = m.group(1);
            PrivateKey privateKey = null;

            try {
                byte[] content = Base64.decode(m.group(2).getBytes("utf-8"));
                KeyFactory fact = KeyFactory.getInstance("RSA");
                PublicKey publicKey;
                ASN1Sequence seq;
                RSAPublicKeySpec pubSpec;
                if (type.equals("RSA PRIVATE KEY")) {
                    seq = ASN1Sequence.getInstance(content);
                    if (seq.size() != 9) {
                        throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
                    }
                    org.bouncycastle.asn1.pkcs.RSAPrivateKey key = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);
                    pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                    RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(key.getModulus(), key.getPublicExponent(), key.getPrivateExponent(), key.getPrime1(), key.getPrime2(), key.getExponent1(), key.getExponent2(), key.getCoefficient());
                    publicKey = fact.generatePublic(pubSpec);
                    privateKey = fact.generatePrivate(privSpec);
                } else if (type.equals("PUBLIC KEY")) {
                    KeySpec keySpec = new X509EncodedKeySpec(content);
                    publicKey = fact.generatePublic(keySpec);
                } else {
                    if (!type.equals("RSA PUBLIC KEY")) {
                        throw new IllegalArgumentException(type + " is not a supported format");
                    }

                    seq = ASN1Sequence.getInstance(content);
                    org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(seq);
                    pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                    publicKey = fact.generatePublic(pubSpec);
                }

                return (RSAPublicKey) new KeyPair(publicKey, privateKey).getPublic();
            } catch (InvalidKeySpecException var11) {
                throw new RuntimeException(var11);
            } catch (NoSuchAlgorithmException var12) {
                throw new IllegalStateException(var12);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private String getKeyString(String keyFile) {
        try {
            InputStream inputStream = JwtDemo.class.getClassLoader().getResourceAsStream(keyFile);
            StringBuilder sb = new StringBuilder();
            int len = 0;
            byte[] bys = new byte[1024];
            while ((len = inputStream.read(bys)) != -1) {
                sb.append(new String(bys, 0, len, "utf-8"));
            }
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
