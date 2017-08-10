package com.mercateo.spring.security.jwt.security.verifier;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import io.vavr.control.Try;
import lombok.val;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JWTVerifierTest {

    private static final String NAMESPACE_PREFIX = "https://test.org/";

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

        uut = new JWTVerifierFactory(jwks).create();
    }

    @Test
    public void shouldVerifyJWT() {
        val originalToken = addVerifiedJWTAuthHeader();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim(NAMESPACE_PREFIX + "user_id").asString()).isEqualTo("<userId>");
        assertThat(jwt.getClaim("scope").asString()).isEqualTo("<scope>");
        assertThat(jwt.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(jwt.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(jwt.getIssuer()).isEqualTo("https://test.org/");

        assertThat(jwt.getClaim("undefined").asString()).isNull();
    }

    private String addVerifiedJWTAuthHeader() {
        val now = System.currentTimeMillis() / 1000 * 1000;
        issuedAt = new Date(now);
        expiresAt = new Date(now + 30000);
        return JWT
            .create()
            .withKeyId(keyId)
            .withClaim(NAMESPACE_PREFIX + "user_id", "<userId>")
            .withClaim(NAMESPACE_PREFIX + "undefined", "<undefined>")
            .withClaim("scope", "<scope>")
            .withIssuedAt(issuedAt)
            .withExpiresAt(expiresAt)
            .withIssuer("https://test.org/")
            .withSubject("<subject>")
            .sign(algorithm);
    }

}
