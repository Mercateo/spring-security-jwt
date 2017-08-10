package com.mercateo.spring.security.jwt.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;

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
            log.warn("no JWT token found {}{}", request.getServletPath(), pathInfo != null ? pathInfo : "");
            throw new InvalidTokenException("no token", new RuntimeException());
        } else {
            String authToken = header.split("\\s+")[1];

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
