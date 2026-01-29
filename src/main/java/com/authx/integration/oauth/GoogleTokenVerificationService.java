package com.authx.integration.oauth;

import com.authx.service.interfaces.IGoogleTokenVerificationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;

import com.authx.dto.response.GoogleUserInfo;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;

/**
 * Google Token Verification Service
 * Third-party integration for Google OAuth token verification
 */
@Slf4j
@Service
public class GoogleTokenVerificationService implements IGoogleTokenVerificationService {
    @Value("${google.client-id}")
    private String googleClientId;

    private final JsonFactory jsonFactory = GsonFactory.getDefaultInstance();

    public GoogleUserInfo verifyGoogleToken(String idToken){
        try{
            HttpTransport transport = GoogleNetHttpTransport.newTrustedTransport();

            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken != null) {
                GoogleIdToken.Payload payload = googleIdToken.getPayload();

                return GoogleUserInfo.builder()
                        .email(payload.getEmail())
                        .firstName(payload.get("given_name").toString())
                        .lastName(payload.get("family_name").toString())
                        .build();
            } else {
                throw new RuntimeException("Invalid Google ID token");
            }
        }catch(Exception e){
            e.printStackTrace();
            throw new RuntimeException("Invalid Google ID token");
        }
    }

}
