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

import java.util.Objects;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.TokenException;
import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;

import io.vavr.collection.List;
import io.vavr.control.Option;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

@Slf4j
@AllArgsConstructor
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final ValidatingHierarchicalClaimsExtractor hierarchicalJWTClaimsExtractor;

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
            claims = hierarchicalJWTClaimsExtractor.extractClaims(tokenString);
        } catch (TokenException e) {
            final String message;
            if (e.getCause() != null && e.getCause().getMessage() != null) {
                message = e.getCause().getMessage();
            } else if (e.getMessage() != null) {
                message = e.getMessage();
            } else {
                message = "failed to extract token";
            }
            throw new InvalidTokenException(message, e);
        }

        val token = JWT.decode(tokenString);
        val subject = token.getSubject();
        val id = subject != null ? subject.hashCode() : 0;
        val authorities = retrieveAuthorities(claims);

        return new JWTPrincipal(id, subject, tokenString, authorities, claims.claims());
    }

    protected List<? extends GrantedAuthority> retrieveAuthorities(JWTClaims claims) {
        val scopes = extractScopes(claims);
        val roles = extractRoles(claims);
        return List //
                .ofAll(scopes)
                .appendAll(roles)
                .map(value -> JWTAuthority.builder().authority(value).build());
    }

    private List<String> extractScopes(JWTClaims claims) {
        return Option.of(claims
                .claims()
                .get("scope"))
                .map(JWTClaim::value)
                .filter(Objects::nonNull)
                .map(value -> ((String) value).split("\\s+"))
                .map(List::of)
                .getOrElse(List.empty());
    }

    private List<String> extractRoles(JWTClaims claims) {
        return Option.of(claims
                .claims()
                .get("roles"))
                .map(JWTClaim::value)
                .filter(Objects::nonNull)
                .map(container -> (Object[]) container)
                .map(List::of)
                .map(list -> list //
                        .map(element -> "ROLE_" + element)
                        .map(String::toUpperCase))
                .getOrElse(List.empty());
    }
}
