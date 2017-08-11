package com.mercateo.spring.security.jwt.token.claim;

import org.immutables.value.Value;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.claim.ImmutableJWTClaims;

import io.vavr.collection.Map;

@Value.Immutable
public interface JWTClaims {
    DecodedJWT token();

    Map<String, JWTClaim> claims();

    @Value.Default
    default int verifiedCount() {
        return 0;
    }

    static ImmutableJWTClaims.Builder builder() {
        return ImmutableJWTClaims.builder();
    }
}
