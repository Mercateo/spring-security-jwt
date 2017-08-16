package com.mercateo.spring.security.jwt.security.config;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.mercateo.spring.security.jwt.security.verifier.JWTVerifierFactory;
import org.immutables.value.Value;

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

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
    default List<String> getOptionalClaims() {
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
