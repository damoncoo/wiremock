package com.hsbc;

import com.github.tomakehurst.wiremock.extension.ResponseTransformerV2;
import com.github.tomakehurst.wiremock.http.Response;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;

/**
 * AESResponseTransformer extends ResponseTransformerV2
 */
public class AESResponseTransformer implements ResponseTransformerV2 {

    @Override
    public Response transform(Response response, ServeEvent serveEvent) {
        // Get request
        LoggedRequest request = serveEvent.getRequest();
        // Extract key and IV from request headers
        String key = request.getHeader("AESHeaderKey");
        String iv = request.getHeader("AESHeaderIV");
        String encryptedBody = encrypt(response.getBodyAsString(), key, iv);

        Map<String, Object> map = new HashMap<>();
        map.put("encData", encryptedBody);
        JSONObject jsonObject = new JSONObject(map);

        return Response.Builder.like(response)
                .but()
                .body(jsonObject.toJSONString())
                .build();
    }

    private String encrypt(String plaintext, String key, String iv) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToByteArray(key), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(hexStringToByteArray(iv));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    @Override
    public String getName() {
        return "aes-encryptor";
    }
}