package com.bsep.pki.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.UUID;

@Service
public class CryptoService {

    @Value("${aes.master.key}")
    private String masterKeyString;

    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA";

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public String generateRandomPassword() {
        return UUID.randomUUID().toString();
    }

    public String encryptAES(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey());
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptAES(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getMasterKey());
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedBytes));
    }

    private SecretKey getMasterKey() {
        byte[] decodedKey = Base64.getDecoder().decode(masterKeyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
