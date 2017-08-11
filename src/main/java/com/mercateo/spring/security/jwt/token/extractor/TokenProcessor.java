package com.mercateo.spring.security.jwt.token.extractor;

import java.util.function.Consumer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.vavr.control.Option;

class TokenProcessor {
    DecodedJWT getNextToken(String tokenString) {
        return JWT.decode(tokenString);
    }

    void memoizePossiblyWrappedToken(DecodedJWT token, Consumer<String> tokenStringConsumer) {
        Option
            .of(token.getClaim(ValidatingHierarchicalClaimsExtractor.WRAPPED_TOKEN_KEY)) //
            .filter(claim -> !claim.isNull())
            .map(Claim::asString)
            .forEach(tokenStringConsumer);
    }
}
