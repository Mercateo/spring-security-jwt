package com.mercateo.spring.security.jwt.token.extractor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.Optional;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.security.verifier.JWKProvider;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import com.mercateo.spring.security.jwt.security.verifier.TestJWTSecurityConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfiguration;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;

import io.vavr.control.Try;
import lombok.val;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { TestJWTSecurityConfiguration.class, JWTSecurityConfiguration.class })
public class HierarchicalJWTClaimsExtractorTest {

    public static final String KEY_ID = "0815";

    @Autowired
    private Optional<JWTSecurityConfig> securityConfig;

    @Autowired
    private HierarchicalJWTClaimsExtractor uut;

    private Algorithm algorithm;

    private Jwk jwk;

    private JWTKeyset jwks;

    @Before
    public void setUp() {
        final JWKProvider jwkProvider = new JWKProvider();
        jwk = jwkProvider.create(KEY_ID);
        algorithm = jwkProvider.getAlgorithm();

        jwks = securityConfig.flatMap(JWTSecurityConfig::jwtKeyset).orElseThrow(() -> new IllegalStateException(
                "could not fetch jwks mock"));
    }

    @Test
    public void shouldVerifySignedToken() throws Exception {
        val tokenString = JWT
            .create()
            .withIssuer("<issuer>")
            .withKeyId(KEY_ID)
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
                .withClaim("bar", "<bar>")
            .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        val claimsByName = claims.claims();
        assertThat(claimsByName.keySet()).containsExactlyInAnyOrder("scope", "foo");

        assertThat(claimsByName.get("scope")).extracting(JWTClaim::value).contains("test");
        assertThat(claimsByName.get("scope").map(JWTClaim::verified).get()).isTrue();
        assertThat(claimsByName.get("foo")).extracting(JWTClaim::value).contains("<foo>");
        assertThat(claimsByName.get("foo").map(JWTClaim::verified).get()).isTrue();
    }

    @Test
    public void shouldExtractNamespacedClaim() throws Exception {
        val tokenString = JWT
                .create()
                .withIssuer("<issuer>")
                .withKeyId(KEY_ID)
                .withClaim("scope", "test")
                .withClaim("https://test.org/foo", "<foo>")
                .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        val claimsByName = claims.claims();
        assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");

        assertThat(claimsByName.get("scope")).extracting(JWTClaim::value).contains("test");
        assertThat(claimsByName.get("scope").map(JWTClaim::verified).get()).isTrue();
        assertThat(claimsByName.get("foo")).extracting(JWTClaim::value).contains("<foo>");
        assertThat(claimsByName.get("foo").map(JWTClaim::verified).get()).isTrue();
    }

    @Test
    public void shouldVerifyWrappedSignedToken() throws Exception {
        val wrappedTokenString = JWT
            .create()
            .withIssuer("<issuer>")
            .withKeyId(KEY_ID)
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .sign(algorithm);

        val tokenString = JWT
            .create()
            .withIssuer("<otherIssuer>")
            .withClaim("scope", "test test2")
            .withClaim("jwt", wrappedTokenString)
            .sign(Algorithm.none());
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        val claims = uut.extractClaims(tokenString);

        val claimsByName = claims.claims();
        assertThat(claimsByName.keySet()).containsExactlyInAnyOrder("scope", "foo");

        final JWTClaim scope = claimsByName.get("scope").get();
        assertThat(scope).extracting(JWTClaim::value).contains("test test2");
        assertThat(scope.verified()).isFalse();
        assertThat(scope.depth()).isEqualTo(0);

        final JWTClaim innerScope = scope.innerClaim().get();
        assertThat(innerScope).extracting(JWTClaim::value).contains("test");
        assertThat(innerScope.verified()).isTrue();
        assertThat(innerScope.depth()).isEqualTo(1);

        val fooClaim = claimsByName.get("foo").get();
        assertThat(fooClaim).extracting(JWTClaim::value).contains("<foo>");
        assertThat(fooClaim.verified()).isTrue();
        assertThat(fooClaim.depth()).isEqualTo(1);
    }

    @Test
    public void shouldFailWithoutSignedToken() {
        final String tokenString = JWT.create().sign(Algorithm.none());

        assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
            .isInstanceOf(MissingSignatureException.class)
            .hasMessage("at least one part of the token should be signed");
    }

    @Test
    public void shouldFailWhenRequiredScopeIsMissing() throws Exception {
        final String tokenString = JWT
                .create()
                .withIssuer("<issuer>")
                .withKeyId(KEY_ID)
                .withClaim("scope", "test")
                .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
                .isInstanceOf(MissingClaimException.class)
                .hasMessage("missing required claim(s): foo");
    }


    @Test
    public void shouldFailWithExpiredToken() throws Exception {
        final String tokenString = JWT
                .create()
                .withIssuer("<issuer>")
                .withKeyId(KEY_ID)
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