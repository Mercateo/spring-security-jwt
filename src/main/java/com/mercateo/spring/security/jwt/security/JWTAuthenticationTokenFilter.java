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
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.AntPathMatcher;

import io.vavr.collection.HashSet;
import io.vavr.collection.Set;

@Slf4j
public class JWTAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

    private final static String TOKEN_HEADER = "authorization";

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private Set<String> unauthenticatedPaths = HashSet.empty();

    public JWTAuthenticationTokenFilter() {
        super("/**");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String tokenHeader = request.getHeader(TOKEN_HEADER);

        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            try {
                handleNoBearerToken(request, response, chain, tokenHeader);
            } catch (InvalidTokenException e) {
                unsuccessfulAuthentication(request, response, e);
            }
        } else {
            super.doFilter(request, response, chain);
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response) {
        String tokenHeader = request.getHeader(TOKEN_HEADER);

        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            return null;
        } else {
            String authToken = tokenHeader.split("\\s+")[1];
            return getAuthenticationManager().authenticate(new JWTAuthenticationToken(authToken));
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        chain.doFilter(request, response);
    }

    private void handleNoBearerToken(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain, String token) throws IOException, ServletException {
        final String pathInfo = String.valueOf(request.getPathInfo()).replace("null", "");
        final String servletPath = String.valueOf(request.getServletPath()).replace("null", "");

        // request URL depends on the default servlet or mounted location
        final String pathToCheck = servletPath + pathInfo;
        log.warn("no JWT token found {} ({})", pathToCheck, token);

        if (isUnauthenticatedPath(pathToCheck)) {
            chain.doFilter(request, response);
        } else {
            throw new InvalidTokenException("no token");
        }
    }

    private boolean isUnauthenticatedPath(String pathToCheck) {
        return !unauthenticatedPaths.toJavaStream().noneMatch(path -> antPathMatcher.match(path,
                pathToCheck));
    }

    public void addUnauthenticatedPaths(Set<String> unauthenticatedPaths) {
        this.unauthenticatedPaths = this.unauthenticatedPaths.addAll(unauthenticatedPaths);
    }
}
