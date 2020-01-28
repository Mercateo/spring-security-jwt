/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.token.verifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
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
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.config.JWTConfigData;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.control.Try;
import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTVerifierTest {

    public static final String AUDIENCE = "<audience>";

    public static final int MILLISECONDS_PER_SECOND = 1000;

    private static final String NAMESPACE_PREFIX = "https://test.org/";

    @Mock
    private JWTKeyset jwks;

    private String keyId = "4711";

    private Algorithm algorithm;

    private JWTVerifier uut;

    private Date expiresAt;

    private Date issuedAt;

    @Before
    public void setUp() {
        final JWKProvider jwkProvider = new JWKProvider();
        final Jwk jwk = jwkProvider.create(keyId);
        algorithm = jwkProvider.getAlgorithm();
        when(jwks.getKeysetForId(keyId)).thenReturn(Try.success(jwk));
        assertThat(jwks.getKeysetForId(keyId)).isNotNull();

        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().build()).create();
    }

    @Test
    public void verifiesJWT() {
        val originalToken = addVerifiedJWTAuthHeader(0, 30);

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
        val originalToken = addVerifiedJWTAuthHeader(0, 30, Tuple.of("aud", AUDIENCE));
        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().addTokenAudiences(AUDIENCE).build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim(NAMESPACE_PREFIX + "user_id").asString()).isEqualTo("<userId>");
        assertThat(jwt.getClaim("scope").asString()).isEqualTo("<scope>");
        assertThat(jwt.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(jwt.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(jwt.getIssuer()).isEqualTo("https://test.org/");

        assertThat(jwt.getClaim("undefined").asString()).isNull();
    }

    @Test
    public void verifiesJWTWithAlternativeAudience() {
        val originalToken = addVerifiedJWTAuthHeader(0, 30, Tuple.of("aud", AUDIENCE));
        uut = new JWTVerifierFactory(jwks, JWTConfigData
            .builder()
            .addTokenAudiences(AUDIENCE)
            .addTokenAudiences("<other>")
            .build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim("aud").asString()).isEqualTo(AUDIENCE);
    }

    @Test
    public void failsVerifyingExpiredToken() {
        val originalToken = addVerifiedJWTAuthHeader(0, -30);
        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().build()).create();

        assertThatThrownBy(() -> uut.verify(originalToken))
            .isInstanceOf(TokenExpiredException.class)
            .hasMessageStartingWith("The Token has expired on ");
    }

    @Test
    public void verifiesOffsetIssuedTokenWithDefaultLeeway() {
        val originalToken = addVerifiedJWTAuthHeader(58, 3600);
        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getIssuedAt()).isAfter(new Date());
    }

    @Test
    public void verifiesOffsetIssuedTokenWithExtendedLeeway() {
        val originalToken = addVerifiedJWTAuthHeader(118, 3600);
        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().tokenLeeway(120).build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getIssuedAt()).isAfter(new Date());
    }

    @Test
    public void verifiesExpiredTokenWithConfiguredLeeway() {
        val originalToken = addVerifiedJWTAuthHeader(0, -30);
        uut = new JWTVerifierFactory(jwks, JWTConfigData.builder().tokenLeeway(35).build()).create();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getExpiresAt()).isBefore(new Date());
    }

    @Test
    public void failsVerifyingMissingAudience() {
        val originalToken = addVerifiedJWTAuthHeader(0, 30);
        final JWTConfig config = JWTConfigData.builder().addTokenAudiences(AUDIENCE).build();
        uut = new JWTVerifierFactory(jwks, config).create();

        assertThatThrownBy(() -> uut.verify(originalToken)) //
            .isInstanceOf(InvalidClaimException.class)
            .hasMessage("The Claim 'aud' value doesn't contain at least one of the required audiences.");
    }

    @SafeVarargs
    private final String addVerifiedJWTAuthHeader(long issued_offset, long expiry_offset,
            Tuple2<String, String>... claims) {

        val now = System.currentTimeMillis() / MILLISECONDS_PER_SECOND * MILLISECONDS_PER_SECOND;
        issuedAt = new Date(now + issued_offset * MILLISECONDS_PER_SECOND);
        expiresAt = new Date(now + expiry_offset * MILLISECONDS_PER_SECOND);
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

    
    @Test
    public void testAlgorithms() {
    	DecodedJWT jwt=mock(DecodedJWT.class);
    	when(jwt.getAlgorithm()).thenReturn("RS256");
		Algorithm algo1 = uut.getAlgorithm(jwt);
		assertEquals("RS256", algo1.getName());
		
		when(jwt.getAlgorithm()).thenReturn("RS384");
		Algorithm algo2 = uut.getAlgorithm(jwt);
		assertEquals("RS384", algo2.getName());
		
		when(jwt.getAlgorithm()).thenReturn("RS512");
		Algorithm algo3 = uut.getAlgorithm(jwt);
		assertEquals("RS512", algo3.getName());
    }
}
