package com.mercateo.spring.security.jwt.token.result;

import java.util.Optional;

import org.immutables.value.Value;

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

    @Value.Default
    default Optional<JWTClaim> innerClaim() {
        return Optional.empty();
    }

    @Value.Default
    default int depth() {
        return 0;
    }

    static ImmutableJWTClaim.Builder builder() {
        return ImmutableJWTClaim.builder();
    }
}
