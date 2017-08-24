package com.mercateo.spring.security.jwt.security.config;

import org.immutables.value.Value;
import org.immutables.vavr.encodings.VavrEncodingEnabled;
import org.springframework.http.HttpMethod;

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.security.verifier.JWTVerifierFactory;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.collection.Set;
import io.vavr.control.Option;

@Value.Immutable
@VavrEncodingEnabled
public interface JWTSecurityConfig {
    Set<String> anonymousPaths();

    Set<HttpMethod> anonymousMethods();

    Option<JWTKeyset> jwtKeyset();

    @Value.Derived
    default Option<JWTVerifier> jwtVerifier() {
        return jwtKeyset().map(JWTVerifierFactory::new).map(JWTVerifierFactory::create);
    }

    Set<String> getRequiredClaims();

    Set<String> getOptionalClaims();

    Set<String> getNamespaces();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
