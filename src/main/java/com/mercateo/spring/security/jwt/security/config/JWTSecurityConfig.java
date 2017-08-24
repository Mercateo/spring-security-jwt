package com.mercateo.spring.security.jwt.security.config;

import io.vavr.collection.List;
import org.immutables.value.Value;
import org.immutables.vavr.encodings.VavrEncodingEnabled;

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.security.verifier.JWTVerifierFactory;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.control.Option;
import org.springframework.http.HttpMethod;

@Value.Immutable
@VavrEncodingEnabled
public interface JWTSecurityConfig {
    List<String> anonymousPaths();

    List<HttpMethod> anonymousMethods();

    Option<JWTKeyset> jwtKeyset();

    @Value.Derived
    default Option<JWTVerifier> jwtVerifier() {
        return jwtKeyset().map(JWTVerifierFactory::new).map(JWTVerifierFactory::create);
    }

    List<String> getRequiredClaims();

    List<String> getOptionalClaims();

    List<String> getNamespaces();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
