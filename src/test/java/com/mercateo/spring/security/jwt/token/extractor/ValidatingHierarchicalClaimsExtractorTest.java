package com.mercateo.spring.security.jwt.token.extractor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.Optional;

import io.vavr.control.Option;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.annotation.Bean;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.control.Try;
import lombok.val;

public class ValidatingHierarchicalClaimsExtractorTest {

    private static final String KEY_ID = "0815";

    private ValidatingHierarchicalClaimsExtractor uut;

    private Algorithm algorithm;

    private Jwk jwk;

    private JWTKeyset jwks;

    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig
            .builder()
            .addAnonymousPaths("/admin/app_health")
            .setValueJwtKeyset(mock(JWTKeyset.class))
            .addNamespaces("https://test.org/")
            .addRequiredClaims("foo")
            .build();
    }

    @Before
    public void setUp() {
        final JWKProvider jwkProvider = new JWKProvider();
        jwk = jwkProvider.create(KEY_ID);
        algorithm = jwkProvider.getAlgorithm();

        val securityConfig = securityConfig();

        jwks = Option.of(securityConfig).flatMap(JWTSecurityConfig::jwtKeyset).getOrElseThrow(
                () -> new IllegalStateException("could not fetch jwks mock"));

        uut = new ValidatingHierarchicalClaimsExtractor(securityConfig);
    }

    private JWTCreator.Builder unsignedJwtBuilder() {
        return JWT.create().withIssuer("<otherIssuer>");
    }

    private JWTCreator.Builder signedJwtBuilder() {
        return JWT.create().withIssuer("<issuer>").withKeyId(KEY_ID);
    }

    private JWTClaim getClaimByName(JWTClaims claims, String name) {
        return claims.claims().get(name).get();
    }

    private void assertClaimContent(JWTClaim claim, String value, boolean verified, int depth) {
        assertThat(claim).extracting(JWTClaim::value).contains(value);
        assertThat(claim.verified()).isEqualTo(verified);
        assertThat(claim.depth()).isEqualTo(depth);
    }

    @Test
    public void extractsVerifiedClaims() throws Exception {
        val tokenString = signedJwtBuilder()
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .withClaim("bar", "<bar>")
            .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");
        assertClaimContent(getClaimByName(claims, "scope"), "test", true, 0);
        assertClaimContent(getClaimByName(claims, "foo"), "<foo>", true, 0);
    }

    @Test
    public void extractsNamespacedClaims() throws Exception {
        val tokenString = signedJwtBuilder().withClaim("scope", "test").withClaim("https://test.org/foo", "<foo>").sign(
                algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");
        assertClaimContent(getClaimByName(claims, "foo"), "<foo>", true, 0);
    }

    @Test
    public void mergesClaimsFromInnerAndOuterToken() throws Exception {
        val wrappedTokenString = signedJwtBuilder().withClaim("scope", "test").withClaim("foo", "<foo>").sign(
                algorithm);

        val tokenString = unsignedJwtBuilder()
            .withClaim("scope", "test test2")
            .withClaim("jwt", wrappedTokenString)
            .sign(Algorithm.none());
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");

        assertClaimContent(getClaimByName(claims, "scope"), "test test2", false, 0);
        assertClaimContent(getClaimByName(claims, "foo"), "<foo>", true, 1);
    }

    @Test
    public void keepsClaimsFromInnerTokenAsInnerClaims() throws Exception {
        val wrappedTokenString = signedJwtBuilder().withClaim("scope", "test").withClaim("foo", "<foo>").sign(
                algorithm);

        val tokenString = unsignedJwtBuilder()
            .withClaim("scope", "test test2")
            .withClaim("jwt", wrappedTokenString)
            .sign(Algorithm.none());
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        final JWTClaim scope = getClaimByName(claims, "scope");
        final JWTClaim innerScope = scope.innerClaim().get();
        assertClaimContent(innerScope, "test", true, 1);
    }

    @Test
    public void throwsExceptionWithoutSignedToken() {
        final String tokenString = JWT.create().sign(Algorithm.none());

        assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
            .isInstanceOf(MissingSignatureException.class)
            .hasMessage("at least one part of the token should be signed");
    }

    @Test
    public void doesNotThrowsExceptionWithoutSignedTokenIfNoValidatorIsConfigured() {
        uut = new ValidatingHierarchicalClaimsExtractor(JWTSecurityConfig.builder().build());
        final String tokenString = JWT.create().sign(Algorithm.none());

        val result = uut.extractClaims(tokenString);

        assertThat(result).isNotNull();
    }

    @Test
    public void throwsExceptionWhenRequiredScopeIsMissing() throws Exception {
        final String tokenString = signedJwtBuilder().withClaim("scope", "test").sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
            .isInstanceOf(MissingClaimException.class)
            .hasMessage("missing required claim(s): foo");
    }

    @Test
    public void throwsExceptionWhenTokenIsExpired() throws Exception {
        final String tokenString = signedJwtBuilder()
            .withClaim("scope", "test")
            .withClaim("https://test.org/foo", "<foo>")
            .withExpiresAt(new Date(System.currentTimeMillis() - 10000))
            .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        assertThatThrownBy(() -> uut.extractClaims(tokenString))
            .isInstanceOf(InvalidTokenException.class)
            .hasMessage("could not verify token")
            .hasCauseInstanceOf(TokenExpiredException.class);
    }
}