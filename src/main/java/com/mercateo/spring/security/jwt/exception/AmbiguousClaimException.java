package com.mercateo.spring.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class AmbiguousClaimException extends AuthenticationException {
    public AmbiguousClaimException(String msg) {
        super(msg);
    }
}
