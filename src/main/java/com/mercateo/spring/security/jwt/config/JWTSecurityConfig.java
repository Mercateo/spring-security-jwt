package com.mercateo.spring.security.jwt.config;

import java.util.List;

import org.immutables.value.Value;

@Value.Immutable
public interface JWTSecurityConfig {
    List<String> anonymousPaths();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
