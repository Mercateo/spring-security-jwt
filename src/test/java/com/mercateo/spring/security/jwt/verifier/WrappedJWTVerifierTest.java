package com.mercateo.spring.security.jwt.verifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.Optional;

import com.mercateo.spring.security.jwt.exception.MissingClaimException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfiguration;
import com.mercateo.spring.security.jwt.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import com.mercateo.spring.security.jwt.result.JWTClaims;

import io.vavr.collection.Map;
import io.vavr.collection.Traversable;
import io.vavr.control.Try;
import lombok.val;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { TestJWTSecurityConfiguration.class, JWTSecurityConfiguration.class })
public class WrappedJWTVerifierTest {

    public static final String KEY_ID = "0815";

    @Autowired
    private Optional<JWTSecurityConfig> securityConfig;

    @Autowired
    private WrappedJWTVerifier uut;

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
        final String tokenString = JWT
            .create()
            .withIssuer("<issuer>")
            .withKeyId(KEY_ID)
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
                .withClaim("bar", "<bar>")
            .sign(algorithm);
        when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

        final JWTClaims claims = uut.collect(tokenString);

        final Map<String, JWTClaim> claimsByName = claims.claims().groupBy(JWTClaim::name).mapValues(Traversable::head);
        assertThat(claims.claims()).extracting(JWTClaim::name).containsExactlyInAnyOrder("scope", "foo");

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

        final JWTClaims claims = uut.collect(tokenString);

        final Map<String, JWTClaim> claimsByName = claims.claims().groupBy(JWTClaim::name).mapValues(Traversable::head);
        assertThat(claims.claims()).extracting(JWTClaim::name).containsExactlyInAnyOrder("scope", "foo");

        assertThat(claimsByName.get("scope")).extracting(JWTClaim::value).contains("test test2");
        assertThat(claimsByName.get("scope").map(JWTClaim::verified).get()).isFalse();
        assertThat(claimsByName.get("foo")).extracting(JWTClaim::value).contains("<foo>");
        assertThat(claimsByName.get("foo").map(JWTClaim::verified).get()).isTrue();
    }

    @Test
    public void shouldFailWithoutSignedToken() {
        final String tokenString = JWT.create().sign(Algorithm.none());

        assertThatThrownBy(() -> uut.collect(tokenString)) //
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

        assertThatThrownBy(() -> uut.collect(tokenString)) //
                .isInstanceOf(MissingClaimException.class)
                .hasMessage("missing required claim(s): foo");
    }
}