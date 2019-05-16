/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;

public class JWKProvider {

    private final RSAPublicKey publicKey;

    private final Algorithm algorithm;

    public JWKProvider() {
        RSAPrivateKey privateKey;
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

        return new Jwk(keyId, "RSA", algorithm.getName(), null, Collections.emptyList(), null, Collections.emptyList(),
                null, additionalValues);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }
}
