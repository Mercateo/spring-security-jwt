package com.mercateo.spring.security.jwt.security.verifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.control.Try;
import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTVerifierTest {

    private static final String NAMESPACE_PREFIX = "https://test.org/";

    public static final String AUDIENCE = "<audience>";

    @Mock
    private JWTKeyset jwks;

    private String keyId = "4711";

    private Algorithm algorithm;

    private JWTVerifier uut;

    private Date expiresAt;

    private Date issuedAt;

    @Before
    public void setUp() throws Exception {
        final JWKProvider jwkProvider = new JWKProvider();
        final Jwk jwk = jwkProvider.create(keyId);
        algorithm = jwkProvider.getAlgorithm();
        when(jwks.getKeysetForId(keyId)).thenReturn(Try.success(jwk));
        assertThat(jwks.getKeysetForId(keyId)).isNotNull();

        uut = new JWTVerifierFactory(jwks, JWTSecurityConfig.builder().build()).create();
    }

    @Test
    public void verifiesJWT() {
        val originalToken = addVerifiedJWTAuthHeader(30000);

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim(NAMESPACE_PREFIX + "user_id").asString()).isEqualTo("<userId>");
        assertThat(jwt.getClaim("scope").asString()).isEqualTo("<scope>");
        assertThat(jwt.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(jwt.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(jwt.getIssuer()).isEqualTo("https://test.org/");

        assertThat(jwt.getClaim("undefined").asString()).isNull();
    }

    @Test
    public void verifiesJWTWithAudience() {
        val originalToken = addVerifiedJWTAuthHeader(30000, Tuple.of("aud", AUDIENCE));
        uut = new JWTVerifierFactory(jwks, JWTSecurityConfig.builder().addTokenAudiences(AUDIENCE).build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim(NAMESPACE_PREFIX + "user_id").asString()).isEqualTo("<userId>");
        assertThat(jwt.getClaim("scope").asString()).isEqualTo("<scope>");
        assertThat(jwt.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(jwt.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(jwt.getIssuer()).isEqualTo("https://test.org/");

        assertThat(jwt.getClaim("undefined").asString()).isNull();
    }

    @Test
    public void failsVerifyingExpiredToken() {
        val originalToken = addVerifiedJWTAuthHeader(-30000);
        uut = new JWTVerifierFactory(jwks, JWTSecurityConfig.builder().build()).create();

        assertThatThrownBy(() -> uut.verify(originalToken))
            .isInstanceOf(TokenExpiredException.class)
            .hasMessageStartingWith("The Token has expired on ");
    }

    @Test
    public void verifiesExpiredTokenWithConfiguredLeeway() {
        val originalToken = addVerifiedJWTAuthHeader(-30000);
        uut = new JWTVerifierFactory(jwks, JWTSecurityConfig.builder().tokenLeeway(35).build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getExpiresAt()).isBefore(new Date());
    }

    @Test
    public void failsVerifyingMissingAudience() {
        val originalToken = addVerifiedJWTAuthHeader(30000);
        final JWTSecurityConfig config = JWTSecurityConfig.builder().addTokenAudiences(AUDIENCE).build();
        uut = new JWTVerifierFactory(jwks, config).create();

        assertThatThrownBy(() -> uut.verify(originalToken)) //
            .isInstanceOf(InvalidClaimException.class)
            .hasMessage("The Claim 'aud' value doesn't contain the required audience.");
    }

    @SafeVarargs
    private final String addVerifiedJWTAuthHeader(long expiry, Tuple2<String, String>... claims) {
        val now = System.currentTimeMillis() / 1000 * 1000;
        issuedAt = new Date(now);
        expiresAt = new Date(now + expiry);
        final JWTCreator.Builder jwtBuilder = JWT
            .create()
            .withKeyId(keyId)
            .withClaim(NAMESPACE_PREFIX + "user_id", "<userId>")
            .withClaim(NAMESPACE_PREFIX + "undefined", "<undefined>")
            .withClaim("scope", "<scope>")
            .withIssuedAt(issuedAt)
            .withExpiresAt(expiresAt)
            .withIssuer("https://test.org/")
            .withSubject("<subject>");

        for (Tuple2<String, String> claim : claims) {
            jwtBuilder.withClaim(claim._1(), claim._2());
        }
        return jwtBuilder.sign(algorithm);
    }

}
