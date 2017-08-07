package com.mercateo.spring.security.jwt.config;

import java.util.List;
import java.util.Optional;

import com.mercateo.spring.security.jwt.verifier.JWTKeyset;
import org.immutables.value.Value;

@Value.Immutable
public interface JWTSecurityConfig {
    List<String> anonymousPaths();

    Optional<JWTKeyset> jwtKeyset();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
