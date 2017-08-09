package com.mercateo.spring.security.jwt.verifier;

import com.auth0.jwk.Jwk;
import io.vavr.control.Try;

public interface JWTKeyset {
    Try<Jwk> getKeysetForId(String keyId);
}
