package com.mercateo.spring.security.jwt.result;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.vavr.collection.Set;
import org.immutables.value.Value;

@Value.Immutable
public interface JWTClaims {
    DecodedJWT token();

    Set<JWTClaim> claims();

    int verifiedCount();

    static ImmutableJWTClaims.Builder builder() {
        return ImmutableJWTClaims.builder();
    }
}
