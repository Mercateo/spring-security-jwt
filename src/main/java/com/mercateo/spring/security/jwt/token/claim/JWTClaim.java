package com.mercateo.spring.security.jwt.token.claim;

import java.util.Optional;

import org.immutables.value.Value;

import com.mercateo.spring.security.jwt.token.claim.ImmutableJWTClaim;

@Value.Immutable
public interface JWTClaim {
    String name();

    String value();

    @Value.Default
    default String issuer() {
        return "";
    }

    @Value.Default
    default boolean verified() {
        return false;
    }

    Optional<JWTClaim> innerClaim();

    @Value.Default
    default int depth() {
        return 0;
    }

    static ImmutableJWTClaim.Builder builder() {
        return ImmutableJWTClaim.builder();
    }
}
