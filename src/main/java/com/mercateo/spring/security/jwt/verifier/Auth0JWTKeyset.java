package com.mercateo.spring.security.jwt.verifier;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import io.vavr.control.Try;

public class Auth0JWTKeyset implements JWTKeyset {

    private JwkProvider provider;

    public Auth0JWTKeyset(String auth0Domain) {
        JwkProvider http = new UrlJwkProvider("https://" + auth0Domain);
        provider = new GuavaCachedJwkProvider(http);
    }

    @Override
    public Try<Jwk> getKeysetForId(String keyId) {
        return Try.of(() -> provider.get(keyId));
    }
}
