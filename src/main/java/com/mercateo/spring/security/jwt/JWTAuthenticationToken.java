package com.mercateo.spring.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class JWTAuthenticationToken extends UsernamePasswordAuthenticationToken {


    private String token;

    public JWTAuthenticationToken(String token) {
        super(null, null);
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
