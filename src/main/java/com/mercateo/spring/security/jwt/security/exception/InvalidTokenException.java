package com.mercateo.spring.security.jwt.security.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String message, Throwable e) {
        super(message, e);
    }

    public InvalidTokenException(String message) {
        super(message);
    }
}
