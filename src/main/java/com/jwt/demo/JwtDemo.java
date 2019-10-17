package com.jwt.demo;

import com.jwt.demo.jwt.JwtHelper;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.io.IOUtils;
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

        JwtHelper jwtHelper = JwtHelper.ofKeystoreAndPassword(keystore, keystorePassword);
        RSAPrivateKey privateKey = jwtHelper.getRsaPrivateKey(alias, keyPassword);

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
    public void checkToken() {

        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiemhhbmdzYW4iLCJleHAiOjE1NzEyOTE2MzAsInVzZXJJZCI6MzIxNDUsImlhdCI6MTU3MTI5MTYxMH0.JaXH3UCNmSUSBtC76K4ApR1NfcVYL1engQapkL-mnzzROVavXUVzu5_sPN4leodUAJgVFUmL1FsrE6Ns19tv-rxK76Kn4AmSeHMKemkUMf4XRkaW2IhIstq0RNpKBOxZcu3Q1L7vPjB1Du6yKvH4RwXQDSRnPcQPjcl0onmPnaNKG0RGfUh4dF8SnKq2a7F1ETNpGNjaauACPC0neuukcSSJkOnRqpalbzm2H-63PwAXX87KiFZM220c2LGxE84pQX7WM1AyqO8E9CCTU_U9O_hOSQr17b_npmrT6c3IxXycOmiK7ffulRt2QV3jJ1G1kS3-Bcvdv-qR_r1skiC2EA";

        RSAPublicKey key = JwtHelper.getPublicKey("publickey.txt");
        Jwt jwt = Jwts.parser().setSigningKey(key).parse(token);

        Map body = (Map)jwt.getBody();
        System.out.println(body);
        Header header = jwt.getHeader();
        System.out.println(header);
    }


}
