package com.mercateo.spring.security.jwt.config;

import java.util.List;

import org.immutables.value.Value;

@Value.Immutable
public interface JwtSecurityConfig {
    List<String> anonymousPaths();

    static ImmutableJwtSecurityConfig.Builder builder() {
        return ImmutableJwtSecurityConfig.builder();
    }
}
