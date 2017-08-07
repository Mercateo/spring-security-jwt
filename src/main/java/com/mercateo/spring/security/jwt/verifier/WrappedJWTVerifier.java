package com.mercateo.spring.security.jwt.verifier;

import java.util.Optional;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@Slf4j
public class WrappedJWTVerifier {

    public static final String WRAPPED_TOKEN_KEY = "jwt";

    private final Optional<JWTVerifier> verifier;

    public void verifyIfPresent(String tokenString) {
        if (!verifier.isPresent()) {
            return;
        }

        DecodedJWT token = JWT.decode(tokenString);

        while (true) {
            if (token.getAlgorithm() != null) {
                verifyIfPresent(token);
            }

            final Claim wrappedTokenClaim = token.getClaim(WRAPPED_TOKEN_KEY);
            if (wrappedTokenClaim.isNull()) {
                break;
            } else {
                token = JWT.decode(wrappedTokenClaim.asString());
            }
        }
    }

    private void verifyIfPresent(DecodedJWT token) {
        verifier.ifPresent(verifier -> {
            log.info("verify token");
            verifier.verify(token.getToken());
        });
    }
}
