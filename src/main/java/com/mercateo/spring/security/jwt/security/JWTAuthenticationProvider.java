package com.mercateo.spring.security.jwt.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.TokenException;
import com.mercateo.spring.security.jwt.token.extractor.HierarchicalJWTClaimExtractor;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;
import com.mercateo.spring.security.jwt.token.result.JWTClaims;

import io.vavr.collection.List;
import lombok.AllArgsConstructor;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final HierarchicalJWTClaimExtractor wrappedJWTExtractor;

    @Override
    public boolean supports(Class<?> authentication) {
        return (JWTAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // intentionally left blank
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        final String tokenString = ((JWTAuthenticationToken) authentication).getToken();

        final JWTClaims claims;
        try {
            claims = wrappedJWTExtractor.extractClaims(tokenString);
        } catch (TokenException e) {
            throw new InvalidTokenException("filed to extract token", e);
        }

        val token = JWT.decode(tokenString);
        val subject = token.getSubject();
        val id = subject.hashCode();

        val authorities = claims
            .claims()
            .get("scope")
            .map(JWTClaim::value)
            .map(value -> value.split("\\s+"))
            .map(List::of)
            .map(list -> list.map(value -> JWTAuthority.builder().authority(value).build()))
            .getOrElse(List.empty());

        return new JWTPrincipal(id, subject, tokenString, authorities, claims.claims());
    }
}
