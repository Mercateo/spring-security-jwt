package com.mercateo.spring.security.jwt.result;

import org.immutables.value.Value;

@Value.Immutable
public interface JWTClaim {
    String name();

    String issuer();

    String value();

    boolean verified();

    static ImmutableJWTClaim.Builder builder() {
        return ImmutableJWTClaim.builder();
    }
}
