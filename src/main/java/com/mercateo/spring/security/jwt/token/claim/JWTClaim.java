package com.mercateo.spring.security.jwt.token.claim;

import org.immutables.value.Value;

import com.mercateo.immutables.DataClass;

import io.vavr.control.Option;

@Value.Immutable
@DataClass
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

    Option<JWTClaim> innerClaim();

    @Value.Default
    default int depth() {
        return 0;
    }

    static ImmutableJWTClaim.Builder builder() {
        return ImmutableJWTClaim.builder();
    }
}
