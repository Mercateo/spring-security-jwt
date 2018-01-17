package com.mercateo.spring.security.jwt;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;

public class JWKProvider {

    private final RSAPrivateKey privateKey;

    private final RSAPublicKey publicKey;

    private final Algorithm algorithm;

    public JWKProvider() {
        try {
            privateKey = (RSAPrivateKey) PemUtils.readPrivateKey(getClass().getResourceAsStream("rsa-private.pem"),
                    "RSA");
            publicKey = (RSAPublicKey) PemUtils.readPublicKey(getClass().getResourceAsStream("rsa-public.pem"), "RSA");
        } catch (IOException e) {
            throw new IllegalStateException("could not create required keys", e);
        }
        algorithm = Algorithm.RSA256(publicKey, privateKey);
    }

    public Jwk create(String keyId) {

        final HashMap<String, Object> additionalValues = new HashMap<>();
        additionalValues.put("n", Base64.encodeBase64String(publicKey.getModulus().toByteArray()));
        additionalValues.put("e", Base64.encodeBase64String(publicKey.getPublicExponent().toByteArray()));

        return new Jwk(keyId, "RSA", algorithm.getName(), null, Collections.emptyList(), null, Collections.emptyList(), null, additionalValues);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }
}
