package com.authx.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@Slf4j
public class JwtKeyConfig {

    private static final String PRIVATE_KEY_PATH = "keys/private.pem";
    private static final String PUBLIC_KEY_PATH = "keys/public.pem";

    @Bean
    public PrivateKey jwtPrivateKey() throws Exception {
        log.info("Loading JWT private key from: {}", PRIVATE_KEY_PATH);
        String privateKeyContent = loadKeyFromFile(PRIVATE_KEY_PATH);
        return parsePrivateKey(privateKeyContent);
    }

    @Bean
    public PublicKey jwtPublicKey() throws Exception {
        log.info("Loading JWT public key from: {}", PUBLIC_KEY_PATH);
        String publicKeyContent = loadKeyFromFile(PUBLIC_KEY_PATH);
        return parsePublicKey(publicKeyContent);
    }

    private String loadKeyFromFile(String filePath) throws IOException {
        // Load from classpath (resources/keys/)
        ClassPathResource resource = new ClassPathResource(filePath);
        if (!resource.exists()) {
            throw new RuntimeException("Key file not found in classpath: " + filePath);
        }

        return new String(resource.getInputStream().readAllBytes())
                .replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                .replaceAll("-----END ([A-Z ]+)-----", "")
                .replaceAll("\\s", "");
    }

    // Parse private key from PEM format and wrap in PKCS8EncodedKeySpec (standard for private keys)
    private PrivateKey parsePrivateKey(String keyContent) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Parse public key from PEM format and wrap in X509EncodedKeySpec (standard for public keys)
    private PublicKey parsePublicKey(String keyContent) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}