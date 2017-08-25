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

    /**
     * @return Paths with anonymous access
     */
    Set<String> anonymousPaths();

    /**
     * @return {@link HttpMethod} with anynomous access
     */
    Set<HttpMethod> anonymousMethods();

    /**
     * @return {@link JWTKeyset} to be used for token verification
     */
    Option<JWTKeyset> jwtKeyset();

    /**
     * @return {@link JWTVerifier} for given {@link JWTKeyset} to be used for token
     *         verification
     */
    @Value.Derived
    default Option<JWTVerifier> jwtVerifier() {
        return jwtKeyset().map(jwks -> new JWTVerifierFactory(jwks, this)).map(JWTVerifierFactory::create);
    }

    /**
     * @return set of required claims
     */
    Set<String> getRequiredClaims();

    /**
     * @return set of claims which should be processed if they exist
     */
    Set<String> getOptionalClaims();

    Set<String> getNamespaces();

    /**
     * @return The default window in seconds in which the Not Before, Issued At and
     *         Expires At Claims will still be valid.
     *
     *         Setting a specific leeway value on a given Claim will override this
     *         value for that Claim.
     */
    @Value.Default
    default int getTokenLeeway() {
        return 0;
    }

    /**
     * @return required Audience ("aud") claims
     */
    Set<String> getTokenAudiences();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
