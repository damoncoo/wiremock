package com.hsbc;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import java.util.Base64;

import com.github.tomakehurst.wiremock.extension.ResponseTransformerV2;
import com.github.tomakehurst.wiremock.http.Response;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

public class RSAResponseTransformer implements ResponseTransformerV2 {

    @Override
    public Response transform(Response response, ServeEvent serveEvent) {
        // Get request
        LoggedRequest request = serveEvent.getRequest();
        // Extract key and IV from request headers
        String key = request.getHeader("X-Encryption-Public-Key");
        // encypt response with RSA
        String encryptedBody = response.getBodyAsString();

        try {
            encryptedBody = encrypt(response.getBodyAsString(), key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Return response
        return Response.Builder.like(response)
                .but()
                .body(encryptedBody)
                .build();
    }

    private String encrypt(String content, String rsa) throws Exception {
        // Read the public key into a byte array
        byte[] publicKeyBytes = rsa.getBytes();
        // Create a public key specification from the byte array
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Instantiate the RSA key factory and generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] dataToEncrypt = content.getBytes();
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public String getName() {
        return "rsa-encryptor";
    }

    @Override
    public boolean applyGlobally() {
        return false;
    }
}
