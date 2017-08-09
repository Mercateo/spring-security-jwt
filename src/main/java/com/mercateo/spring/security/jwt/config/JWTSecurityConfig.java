package com.mercateo.spring.security.jwt.config;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.immutables.value.Value;

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.verifier.JWTKeyset;
import com.mercateo.spring.security.jwt.verifier.JWTVerifierFactory;

@Value.Immutable
public interface JWTSecurityConfig {
    @Value.Default
    default List<String> anonymousPaths() {
        return Collections.emptyList();
    }

    Optional<JWTKeyset> jwtKeyset();

    @Value.Derived
    default Optional<JWTVerifier> jwtVerifier() {
        return jwtKeyset().map(JWTVerifierFactory::new).map(JWTVerifierFactory::create);
    }

    @Value.Default
    default List<String> getRequiredClaims() {
        return Collections.emptyList();
    }

    @Value.Default
    default List<String> getNamespaces() {
        return Collections.emptyList();
    }

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
