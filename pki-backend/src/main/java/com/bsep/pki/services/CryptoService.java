package com.bsep.pki.services;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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


    public SecretKey getMasterKey() {
        if (masterKeyString.length() != 32) {
            throw new IllegalArgumentException("Master Key must be 32 characters long for AES-256.");
        }

        byte[] keyBytes = masterKeyString.getBytes(StandardCharsets.UTF_8);

        return new SecretKeySpec(keyBytes, "AES");
    }

    public String privateKeyToPem(PrivateKey privateKey) throws IOException {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(privateKey);
        }
        return writer.toString();
    }


    /**
     * Enkriptuje plaintext koristeći RSA algoritam sa javnim ključem i OAEP paddingom.
     * Preporučeno za enkripciju manjih podataka, npr. AES ključa.

     */
    public String encryptRSAWithPublicKey(String plaintext, PublicKey publicKey)
            throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    public String publicKeyToPem(PublicKey publicKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.close();
        return stringWriter.toString();
    }

    public PublicKey pemToPublicKey(String pemContent) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemReader pemReader = new PemReader(new StringReader(pemContent));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        byte[] publicKeyBytes = pemObject.getContent();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Pretpostavka da je RSA
        return keyFactory.generatePublic(keySpec);
    }

    // Za End-Entity privatni ključ
    public String privateKeyToPemm(PrivateKey privateKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        pemWriter.close();
        return stringWriter.toString();
    }

    public PrivateKey pemToPrivateKey(String pemContent) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemReader pemReader = new PemReader(new StringReader(pemContent));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        byte[] privateKeyBytes = pemObject.getContent();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

}
