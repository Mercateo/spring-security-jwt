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
package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;

import io.vavr.collection.HashMap;
import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationProviderTest {

    @Mock
    private ValidatingHierarchicalClaimsExtractor hierarchicalJWTClaimsExtractor;

    @InjectMocks
    private JWTAuthenticationProvider uut;

    @Test
    public void shouldMapExtractedClaims() {
        val tokenString = JWT.create().withSubject("<subject>").sign(Algorithm.none());
        val tokenContainer = new JWTAuthenticationToken(tokenString);

        final java.util.Map<String, JWTClaim> claimsMap = HashMap.of( //
                "bar", JWTClaim.builder().value("baz").name("bar").build()).toJavaMap();

        JWTClaims claims = JWTClaims.builder().claims(claimsMap).token(JWT.decode(tokenString)).build();

        when(hierarchicalJWTClaimsExtractor.extractClaims(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("<subject>");
        assertThat(((JWTPrincipal) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).isEmpty();
    }

    @Test
    public void shouldMapScopesToGrantedAuthorities() {
        val tokenString = JWT.create().sign(Algorithm.none());
        val tokenContainer = new JWTAuthenticationToken(tokenString);

        final java.util.Map<String, JWTClaim> claimsMap = HashMap.of( //
                "scope", JWTClaim.builder().name("scope").value("foo bar").build()).toJavaMap();

        JWTClaims claims = JWTClaims.builder().claims(claimsMap).token(JWT.decode(tokenString)).build();
        when(hierarchicalJWTClaimsExtractor.extractClaims(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isNull();
        assertThat(((JWTPrincipal) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactlyInAnyOrder(
                "foo", "bar");
    }

    @Test
    public void shouldMapRolesToGrantedAuthorities() {
        val tokenString = JWT.create().sign(Algorithm.none());
        val tokenContainer = new JWTAuthenticationToken(tokenString);

        final java.util.Map<String, JWTClaim> claimsMap = HashMap.of( //
                "roles", JWTClaim.builder().name("roles").value(new Object[]{"foo", "bar"}).build()).toJavaMap();

        JWTClaims claims = JWTClaims.builder().claims(claimsMap).token(JWT.decode(tokenString)).build();
        when(hierarchicalJWTClaimsExtractor.extractClaims(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isNull();
        assertThat(((JWTPrincipal) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactlyInAnyOrder(
                "ROLE_FOO", "ROLE_BAR");
    }

    @Test
    public void shouldSupportJWTAuthToken() {
        assertThat(uut.supports(JWTAuthenticationToken.class)).isTrue();
    }

    @Test
    public void shouldNoSupportJWTAuthTokenSuperclass() {
        assertThat(uut.supports(JWTAuthenticationToken.class.getSuperclass())).isFalse();
    }

    @Test
    public void throwsInvalidTokenExceptionAtErrorDuringExtract() {
        val tokenString = "<token>";

        val exception = new InvalidTokenException(null, new RuntimeException());
        when(hierarchicalJWTClaimsExtractor.extractClaims(tokenString)).thenThrow(exception);

        val tokenContainer = new JWTAuthenticationToken(tokenString);
        assertThatThrownBy(() -> uut.retrieveUser("<userName>", tokenContainer))
            .isInstanceOf(InvalidTokenException.class)
            .hasMessage("failed to extract token")
            .hasCause(exception);
    }
}