package com.mercateo.spring.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.extractor.WrappedJWTExtractor;
import com.mercateo.spring.security.jwt.result.JWTAuthority;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import com.mercateo.spring.security.jwt.result.JWTClaims;

import io.vavr.collection.List;
import lombok.AllArgsConstructor;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final WrappedJWTExtractor wrappedJWTExtractor;

    @Override
    public boolean supports(Class<?> authentication) {
        return (JWTAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        final String tokenString = ((JWTAuthenticationToken) authentication).getToken();
        final JWTClaims claims = wrappedJWTExtractor.collect(tokenString);

        val token = JWT.decode(tokenString);
        val subject = token.getSubject();
        val id = (long) subject.hashCode();

        val authorities = claims.claims().get("scope").map(JWTClaim::value).map(value -> value.split("\\s+")).map(List::of).map(
                list -> list.map(value -> JWTAuthority.builder().authority(value).build())).getOrElse(List.empty());

        return new Authenticated(id, subject, tokenString, authorities, claims.claims());
    }
}
