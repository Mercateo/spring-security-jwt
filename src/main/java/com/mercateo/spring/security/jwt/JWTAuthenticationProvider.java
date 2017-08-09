package com.mercateo.spring.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import com.mercateo.spring.security.jwt.result.JWTClaims;
import com.mercateo.spring.security.jwt.verifier.WrappedJWTVerifier;

import io.vavr.collection.List;
import io.vavr.collection.Map;
import io.vavr.collection.Traversable;
import lombok.AllArgsConstructor;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final WrappedJWTVerifier wrappedJWTVerifier;

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
        final JWTClaims claims = wrappedJWTVerifier.collect(tokenString);

        val token = JWT.decode(tokenString);
        val subject = token.getSubject();
        val id = (long) subject.hashCode();

        List<GrantedAuthority> authorityList = List.empty();

        final Map<String, String> claimsMap = claims
            .claims()
            .groupBy(JWTClaim::name)
            .mapValues(Traversable::head)
            .mapValues(JWTClaim::value);
        return new Authenticated(id, "subject", tokenString, authorityList, claimsMap);
    }
}
