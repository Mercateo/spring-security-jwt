package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.mercateo.spring.security.jwt.token.extractor.WrappedJWTExtractor;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;
import com.mercateo.spring.security.jwt.token.result.JWTClaims;

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

        when(wrappedJWTExtractor.extract(tokenString)).thenReturn(claims);

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
        when(wrappedJWTExtractor.extract(tokenString)).thenReturn(claims);

        val userDetails = uut.retrieveUser("<username>", tokenContainer);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("<subject>");
        assertThat(((Authenticated) userDetails).getToken()).isEqualTo(tokenString);
        assertThat(userDetails.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactlyInAnyOrder(
                "foo", "bar");
    }

    @Test
    public void shouldSupportJWTAuthToken() throws Exception {
        assertThat(uut.supports(JWTAuthenticationToken.class)).isTrue();
    }

    @Test
    public void shouldNoSupportJWTAuthTokenSuperclass() throws Exception {
        assertThat(uut.supports(JWTAuthenticationToken.class.getSuperclass())).isFalse();
    }
}