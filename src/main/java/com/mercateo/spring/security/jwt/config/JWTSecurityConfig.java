package com.mercateo.spring.security.jwt.config;

import org.immutables.value.Value;

import com.mercateo.spring.security.jwt.verifier.JWTKeyset;

import java.util.List;
import java.util.Optional;

@Value.Immutable
public interface JWTSecurityConfig {
    List<String> anonymousPaths();

    Optional<JWTKeyset> jwtKeyset();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
