package com.mercateo.spring.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String msg, Throwable e) {
        super(msg, e);
    }
}
