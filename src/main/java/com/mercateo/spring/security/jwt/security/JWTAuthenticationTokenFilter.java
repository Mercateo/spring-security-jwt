/**
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

import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.AntPathMatcher;

import io.vavr.collection.Set;

@Slf4j
public class JWTAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

    private final static String TOKEN_HEADER = "authorization";

    private final AntPathMatcher antPathMatcher =  new AntPathMatcher();

    @NonNull
    private Set<String> unauthenticatedPaths;

    public JWTAuthenticationTokenFilter(@NonNull Set<String> unauthenticatedPaths) {
        super("/**");
        this.unauthenticatedPaths = unauthenticatedPaths;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String tokenHeader = request.getHeader(TOKEN_HEADER);

        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            final String pathInfo = String.valueOf(request.getPathInfo()).replace("null","");
            final String servletPath = String.valueOf(request.getServletPath()).replace("null","");

            // request URL depends on the default servlet or mounted location
            final String pathToCheck = servletPath + pathInfo;

            log.warn("no JWT token found {} ({})", pathToCheck, tokenHeader);

            if (unauthenticatedPaths.toJavaStream().filter(path -> antPathMatcher.match(path, pathToCheck)).count() == 0) {
                throw new InvalidTokenException("no token");
            } else {
                AnonymousAuthenticationProvider anonymProvider = new AnonymousAuthenticationProvider("anonymousUser");
                return anonymProvider.authenticate(new AnonymousAuthenticationToken("anonymousUser",
                     "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
            }
        } else {
            String authToken = tokenHeader.split("\\s+")[1];

            return getAuthenticationManager().authenticate(new JWTAuthenticationToken(authToken));
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        chain.doFilter(request, response);
    }
}
