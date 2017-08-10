package com.mercateo.spring.security.jwt.token.extractor;

import static java.lang.Boolean.FALSE;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;

import io.vavr.Function2;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.AllArgsConstructor;
import lombok.val;

@AllArgsConstructor
class TokenVerifier {

    private final Option<JWTVerifier> verifier;

    boolean verifyToken(DecodedJWT token) {
        val verifyToken = Function2.of(this::verify).apply(token);

        return verifier //
            .filter(ignore -> !"none".equals(token.getAlgorithm()))
            .map(verifyToken)
            .getOrElse(FALSE).booleanValue();
    }

    private boolean verify(DecodedJWT token, JWTVerifier verifier) {
        return Try
            .of(() -> verifier.verify(token.getToken())) //
            .onFailure(e -> {
                throw new InvalidTokenException("could not verify token", e);
            })
            .isSuccess();
    }
}
