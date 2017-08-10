package com.mercateo.spring.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.extractor.WrappedJWTExtractor;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import com.mercateo.spring.security.jwt.result.JWTClaims;

import io.vavr.collection.HashMap;
import io.vavr.collection.Map;
import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationProviderTest {

    @Mock
    private WrappedJWTExtractor wrappedJWTExtractor;

    @InjectMocks
    private JWTAuthenticationProvider uut;

    @Test
    public void shouldMapExtractedClaims() throws Exception {
        val tokenString = JWT.create().withSubject("<subject>").sign(Algorithm.none());
        val tokenContainer = new JWTAuthenticationToken(tokenString);

        final Map<String, JWTClaim> claimsMap = HashMap.of( //
                "bar", JWTClaim.builder().value("baz").name("bar").build());

        JWTClaims claims = JWTClaims.builder().claims(claimsMap).token(JWT.decode(tokenString)).build();

        when(wrappedJWTExtractor.collect(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("<subject>");
        assertThat(((Authenticated) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).isEmpty();
    }

    @Test
    public void shouldMapScopesToGrantedAuthorities() throws Exception {
        val tokenString = JWT.create().withSubject("<subject>").sign(Algorithm.none());
        val tokenContainer = new JWTAuthenticationToken(tokenString);

        final Map<String, JWTClaim> claimsMap = HashMap.of( //
                "scope", JWTClaim.builder().name("scope").value("foo bar").build());

        JWTClaims claims = JWTClaims.builder().claims(claimsMap).token(JWT.decode(tokenString)).build();
        when(wrappedJWTExtractor.collect(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("<subject>");
        assertThat(((Authenticated) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactlyInAnyOrder(
                "foo", "bar");
    }
}