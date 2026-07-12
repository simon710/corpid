package com.asl.corpid.helper;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class CryptoUtils {
    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    private CryptoUtils() {
    }

    static String generateNonce() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    static String hmacSha256Base64(String message, String secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA_256));
            byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException ex) {
            throw new CorpidException("Failed to generate HMAC-SHA256 signature", ex);
        }
    }

    static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    static String encryptAesGcmBase64(byte[] plain, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            byte[] encrypted = cipher.doFinal(plain);
            ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + encrypted.length);
            buffer.putInt(iv.length);
            buffer.put(iv);
            buffer.put(encrypted);
            return Base64.getEncoder().encodeToString(buffer.array());
        } catch (GeneralSecurityException ex) {
            throw new CorpidException("Failed to encrypt content with CEK", ex);
        }
    }

    static byte[] decryptAesGcmBase64ToBytes(String encryptedBase64, byte[] key) {
        try {
            byte[] content = Base64.getDecoder().decode(encryptedBase64);
            ByteBuffer buffer = ByteBuffer.wrap(content);
            int ivLength = buffer.getInt();
            if (ivLength != 12) {
                throw new CorpidException("Invalid IV length in encrypted payload: " + ivLength);
            }
            byte[] iv = new byte[ivLength];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException ex) {
            throw new CorpidException("Failed to decrypt content with CEK", ex);
        }
    }

    static byte[] decryptRsaBase64(String encryptedBase64, PrivateKey privateKey) {
        String[] transformations = {
                "RSA/ECB/PKCS1Padding",
                "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        };
        GeneralSecurityException lastError = null;
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);
            for (String transformation : transformations) {
                try {
                    Cipher cipher = Cipher.getInstance(transformation);
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    return cipher.doFinal(encrypted);
                } catch (GeneralSecurityException ex) {
                    lastError = ex;
                }
            }
            throw new CorpidException("Failed to decrypt CEK with KEK private key", lastError);
        } catch (IllegalArgumentException ex) {
            throw new CorpidException("Invalid base64 for encrypted CEK", ex);
        }
    }

    static PrivateKey loadPrivateKeyFromP12(Path p12Path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(p12Path)) {
                keyStore.load(in, password.toCharArray());
            }
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Key key = keyStore.getKey(alias, password.toCharArray());
                if (key instanceof PrivateKey privateKey) {
                    return privateKey;
                }
            }
            throw new CorpidException("No private key found in PKCS12 file: " + p12Path);
        } catch (IOException | GeneralSecurityException ex) {
            throw new CorpidException("Failed to load KEK private key from PKCS12", ex);
        }
    }

    static PrivateKey loadPrivateKeyFromPkcs8(String privateKeyText) {
        try {
            String normalized = privateKeyText
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(normalized);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new CorpidException("Failed to load KEK private key from PKCS8 text", ex);
        }
    }
}
