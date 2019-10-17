package com.jwt.demo.jwt;

import com.jwt.demo.JwtDemo;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtHelper {

    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", 32);
    private static volatile KeyStore keyStore;

    private JwtHelper() {

    }

    public static JwtHelper ofKeystoreAndPassword(String keystore, String keystorePassword) {
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
            return new JwtHelper();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (KeyStoreException e) {
            throw new IllegalArgumentException(e);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public RSAPrivateKey getRsaPrivateKey(String alias, String keyPassword) {
        try {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey(alias, keyPassword.toCharArray());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            KeyPair keyPair = new KeyPair(publicKey, key);
            return (RSAPrivateKey) keyPair.getPrivate();
        } catch (KeyStoreException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (UnrecoverableKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static RSAPublicKey getPublicKey(String keyFile) {
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
                    RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(key.getModulus(), key.getPublicExponent(),
                            key.getPrivateExponent(), key.getPrime1(), key.getPrime2(), key.getExponent1(), key.getExponent2(),
                            key.getCoefficient());
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
            } catch (UnsupportedEncodingException var13) {
                throw new IllegalStateException(var13);
            }
        }
    }

    private static String getKeyString(String keyFile) {
        try {
            InputStream inputStream = JwtDemo.class.getClassLoader().getResourceAsStream(keyFile);
            return IOUtils.toString(inputStream, "utf-8");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
