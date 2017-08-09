package com.mercateo.spring.security.jwt.config;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.immutables.value.Value;

import com.auth0.jwt.JWTVerifier;


@Value.Immutable
public interface JWTAuthenticationConfig {
    List<String> getRequiredClaims();

    @Value.Default
    default List<String> getNamespaces() {
        return Collections.emptyList();
    }

    static ImmutableJWTAuthenticationConfig.Builder builder() {
        return ImmutableJWTAuthenticationConfig.builder();
    }
}
