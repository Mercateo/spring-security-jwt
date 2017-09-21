package com.mercateo.spring.security.jwt.token.verifier;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
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

        val verification = JWT.require(algorithm);

        verification.acceptLeeway(config.getTokenLeeway());

        val tokenAudiences = config.getTokenAudiences();
        if (tokenAudiences.nonEmpty()) {
            verification.withAudience(tokenAudiences.toJavaArray(String.class));
        }

        return verification.build();
    }

    private static IllegalStateException map(Throwable cause) {
        return new IllegalStateException(cause);
    }
}
