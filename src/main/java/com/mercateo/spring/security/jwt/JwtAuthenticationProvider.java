package com.mercateo.spring.security.jwt;

import java.util.function.Function;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.exception.MissingClaimException;

import javaslang.collection.HashMap;
import javaslang.collection.List;
import javaslang.collection.Map;
import javaslang.control.Option;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationProvider<E extends Enum<E>> extends AbstractUserDetailsAuthenticationProvider {

    private final Class<E> enumClass;

    private final String namespacePrefix;

    public JwtAuthenticationProvider(Class<E> enumClass, String namespacePrefix) {
        this.enumClass = enumClass;
        this.namespacePrefix = namespacePrefix;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        return Option
            .of((JwtAuthenticationToken) authentication)
            .map(JwtAuthenticationToken::getToken)
            .toTry()
            .mapTry(JWT::decode)
            .onFailure(e -> {
                log.warn("invalid token");
                throw new InvalidTokenException("JWT token is not valid", e);
            })
            .map(this::mapToken)
            .get();
    }

    private UserDetails mapToken(DecodedJWT token) {
        List<GrantedAuthority> authorityList = List.empty();

        final String subject = token.getSubject();
        final long id = subject.hashCode();

        Map<E, String> requiredClaims = List
            .of(enumClass.getEnumConstants())
            .groupBy(Function.identity())
            .mapValues(List::head)
            .mapValues(Enum::name)
            .mapValues(String::toLowerCase)
            .mapValues(name -> determineClaim(token, name));

        return new Authenticated<E>(id, "subject", token.getToken(), authorityList.toJavaList(), requiredClaims
            .toJavaMap());
    }

    private String determineClaim(DecodedJWT token, String claimName) {
        final Map<String, Claim> claims = HashMap.ofAll(token.getClaims());

        if (claims.containsKey(claimName) && claims.get(claimName).map(claim -> !claim.isNull()).getOrElse(false)) {
            return claims.get(claimName).get().asString();
        } else if (claims.containsKey(namespacePrefix + claimName) && claims
            .get(namespacePrefix + claimName)
            .map(claim -> !claim.isNull())
            .getOrElse(false)) {
            return claims.get(namespacePrefix + claimName).get().asString();
        } else {
            log.warn("claim '{}' missing from JWT token", claimName);
            throw new MissingClaimException("JWT token does not contain required claim '" + claimName + "'");
        }
    }
}
