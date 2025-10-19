package com.bsep.pki.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

@Service
public class KeystoreService {

    @Value("${keystore.storage.path}")
    private String keystoreBasePath;

    private static final String KEYSTORE_TYPE = "PKCS12";

    public KeyStore loadKeyStore(Long keystoreId, char[] password) throws Exception {
        File keystoreFile = getKeystoreFile(keystoreId);
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        if (!keystoreFile.exists()) {
            ks.load(null, password);
        } else {
            try (InputStream is = new FileInputStream(keystoreFile)) {
                ks.load(is, password);
            }
        }
        return ks;
    }

    public void saveKeyStore(KeyStore ks, Long keystoreId, char[] password) throws Exception {
        File keystoreFile = getKeystoreFile(keystoreId);
        keystoreFile.getParentFile().mkdirs();
        try (OutputStream os = new FileOutputStream(keystoreFile)) {
            ks.store(os, password);
        }
    }

    public PrivateKey getPrivateKey(Long keystoreId, char[] password, String alias) throws Exception {
        KeyStore ks = loadKeyStore(keystoreId, password);
        return (PrivateKey) ks.getKey(alias, password);
    }

    public Certificate[] getCertificateChain(Long keystoreId, char[] password, String alias) throws Exception {
        KeyStore ks = loadKeyStore(keystoreId, password);
        return ks.getCertificateChain(alias);
    }

    private File getKeystoreFile(Long keystoreId) {
        return new File(keystoreBasePath, "keystore_" + keystoreId + ".p12");
    }
}

