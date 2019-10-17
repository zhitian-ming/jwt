package com.jwt.demo;

import com.alibaba.fastjson.JSON;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;
import org.springframework.security.jwt.codec.Codecs;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtDemo {

    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", 32);
    private static volatile KeyStore keyStore;

    public static void main(String[] args) {
        //密钥库文件
        String keystore = "yj.keystore";
        //密钥库密码
        String keystore_password = "yjpass";

        //密钥别名
        String alias = "yjkey";
        //密钥访问密码
        String key_password = "yjpass";

        RSAPrivateKey privateKey = getRsaPrivateKey(keystore_password, alias, key_password);
        Map<String, Object> headerMap = new HashMap<String, Object>();
        headerMap.put("alg", SignatureAlgorithm.RS256);
        headerMap.put("typ", "JWT");
        Map<String, Object> payload = new HashMap<>();
        payload.put("name", "zhangsan");
        payload.put("userId", 32145);

        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(currentDate.getTime() + 20000));
        Date expTime = calendar.getTime();
        String compact = Jwts.builder().setHeader(headerMap).setClaims(payload).setIssuedAt(currentDate).setExpiration(expTime)
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();
        System.out.println(compact);
        /*
        eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiemhhbmdzYW4iLCJ1c2VySWQiOjMyMTQ1fQ.cDY2x4pnb_ddBLtOZyJ69Ih5_SzLiP7HxTaj176vU88G9r9C1Xp5zTwSyq-TGEBCPxWPkipPTKX4p3ouuz_0snOxf7IGU9K3j2vDstuZBuDAgC7aLSWEzcyw9thRtbHL0tOV7xlD3VzUR01EoevYJSWWiiJ1eCig5U2-fhIH3PgP0ZrzbmdmIRa_xcALeBLwJdwdKje5LEdLm-vm89z6vCul-RHcLK76X6qLSYxHK20KDoRpzNDoonAGDPhqoLBitKOIFd-TlzRKHgruBgFqfAaWaodjZF_yRmlqWleErFP5oAIhxXxl8TKEcwzqDVc9FzqRvAtYwNR2Kzka8iAItA
         */

    }

    private static RSAPrivateKey getRsaPrivateKey(String keystore_password, String alias, String key_password) {
        try {
            if (keyStore == null) {
                synchronized (JwtDemo.class) {
                    if (keyStore == null) {
                        keyStore = KeyStore.getInstance("jks");
                        InputStream inputStream = JwtDemo.class.getClassLoader().getResourceAsStream("yj.keystore");
                        keyStore.load(inputStream, keystore_password.toCharArray());
                    }
                }
            }
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey(alias, key_password.toCharArray());
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

    @Test
    public void decode() {

        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiemhhbmdzYW4iLCJleHAiOjE1NzEyODA5NDAsInVzZXJJZCI6MzIxNDUsImlhdCI6MTU3MTI4MDkyMH0.kAoVTkttPw9YFga1FRuMoEC4swx5IGH1yOEYoSZ8ySH_jBjzQ-H4rGZGBrHpR984c5c6okIxONlUcY-RVph_0P1GrGY9PY5MhUhNgOHRUDTD_Z_HP8zxeHNIj6uoPWMC_U5M9ubH4QokOBoy0SZu43BgZmOlN5H1o2iVfbLzyWm7kLITQJFDSSAIeviXUxqii2DRhG8uR_UlsMBbTup1Vn_hYavOQpP-msPd-k6zDLo7TXy1IjoNvH_wu1bbANOAkUSTyFYe3wmXh18pfvyuRXTXqo2mnPHxcOJFfbR_e-MjT7sXktEi_3F7cUy3Sn78lbigBgw5j3wE09tzgq4fHQ";

        RSAPublicKey key = getPublicKey("publickey.txt");

        Jwt jwt = Jwts.parser().setSigningKey(key).parse(token);
        Map body = (Map)jwt.getBody();
        Header header = jwt.getHeader();
        System.out.println(header);
        System.out.println(body);
    }

    private RSAPublicKey getPublicKey(String keyFile) {
        Matcher m = PEM_DATA.matcher(getKeyString(keyFile).trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        } else {
            String type = m.group(1);
            byte[] content = Codecs.b64Decode(Codecs.utf8Encode(m.group(2)));
            PrivateKey privateKey = null;

            try {
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
            }
        }
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
