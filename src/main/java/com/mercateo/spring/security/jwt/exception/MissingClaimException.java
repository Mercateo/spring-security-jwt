package com.mercateo.spring.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class MissingClaimException extends AuthenticationException {
    public MissingClaimException(String msg) {
        super(msg);
    }
}
