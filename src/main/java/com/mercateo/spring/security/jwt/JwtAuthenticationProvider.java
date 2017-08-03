package com.mercateo.spring.security.jwt;

import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.unite.tenant.adapters.rest.security.exception.InvalidTokenException;

import javaslang.collection.List;
import javaslang.control.Option;
import lombok.val;

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
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String tokenString = jwtAuthenticationToken.getToken();

        final DecodedJWT token = JWT.decode(tokenString);

        if (false)
            throw new InvalidTokenException("JWT token is not valid");

        List<GrantedAuthority> authorityList = List.empty();

        final String subject = token.getSubject();
        final long id = subject.hashCode();

        val requiredClaims = List.of(enumClass.getEnumConstants())
                .groupBy(Function.identity())
                .mapValues(List::head)
                .mapValues(Enum::name)
                .mapValues(String::toLowerCase)
                .mapValues(name -> determineClaim(token, name));

        final UUID tenantId = extractUuid(token, "https://unite.com/tenant_id").orElse(extractUuid(token, "tenant_id")).getOrElseThrow(() -> new AuthenticationException("no tenantId found") {
        });
        final Option<UUID> companyId = extractUuid(token, "https://unite.com/company_id").orElse(extractUuid(token, "company_id"));
        return new AuthenticatedUser<E>(id, "subject", tokenString, authorityList.toJavaList(), requiredClaims.toJavaMap());
    }

    private String determineClaim(DecodedJWT token, String claimName) {
        final Map<String, Claim> claims = token.getClaims();

        if (claims.containsKey(claimName) && !claims.get(claimName).isNull()) {
            return claims.get(claimName).asString();
        } else if (claims.containsKey(namespacePrefix + claimName) && !claims.get(namespacePrefix + claimName).isNull()) {
            return claims.get(namespacePrefix + claimName).asString();
        } else {
            throw new AuthenticationException("JWT token does not contain required claim '" + claimName + "'") {
            };
        }
    }

    private Option<UUID> extractUuid(DecodedJWT token, String claimName) {
        final Claim claim = token.getClaim(claimName);
        if (!claim.isNull()) {
            return Option.some(claim).map(Claim::asString).map(UUID::fromString);
        }
        return Option.none();
    }

}
