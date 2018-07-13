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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.mercateo.spring.security.jwt.security.exception.InvalidTokenException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

    private final static String TOKEN_HEADER = "authorization";

    public JWTAuthenticationTokenFilter() {
        super("/**");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String header = request.getHeader(TOKEN_HEADER);

        if (header == null || !header.startsWith("Bearer ")) {
            final String pathInfo = request.getPathInfo();
            log.warn("no JWT token found {}{} ({})", request.getServletPath(), pathInfo != null ? pathInfo : "",
                    header);
            throw new InvalidTokenException("no token");
        } else {
            String authToken = header.split("\\s+")[1];

            try {
                return getAuthenticationManager().authenticate(new JWTAuthenticationToken(
                        authToken));
            } catch (JWTDecodeException e) {
                throw new InvalidTokenException("invalid token", e);
            }
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        chain.doFilter(request, response);
    }
}
