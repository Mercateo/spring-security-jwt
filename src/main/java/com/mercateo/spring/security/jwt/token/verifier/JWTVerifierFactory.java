/**
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
package com.mercateo.spring.security.jwt.token.verifier;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import lombok.AllArgsConstructor;
import lombok.val;
import lombok.extern.slf4j.Slf4j;
import sun.security.rsa.RSAPublicKeyImpl;

@AllArgsConstructor
@Slf4j
public class JWTVerifierFactory {
    final JWTKeyset jwks;

    final JWTConfig config;

    private static IllegalStateException map(Throwable cause) {
        return new IllegalStateException(cause);
    }

    public JWTVerifier create() {
        final RSAKeyProvider rsaKeyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return jwks
                    .getKeysetForId(keyId)
                    .mapTry(Jwk::getPublicKey)
                    .map(Key::getEncoded)
                    .mapTry(RSAPublicKeyImpl::new)
                    .onFailure(e -> log.warn("Error getting public key for id " + keyId, e))
                    .getOrElseThrow(JWTVerifierFactory::map);
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };

        val algorithm = Algorithm.RSA256(rsaKeyProvider);

        val verification = JWTVerifier.init(algorithm);

        final int tokenLeeway = config.getTokenLeeway();
        verification.acceptLeeway(tokenLeeway);

        val tokenAudiences = config.getTokenAudiences();
        if (tokenAudiences.nonEmpty()) {
            verification.withAudience(tokenAudiences.toJavaArray(String.class));
        }

        return verification.build();
    }
}
