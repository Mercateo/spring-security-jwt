package com.mercateo.spring.security.jwt.token.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends TokenException {
    public InvalidTokenException(String msg, Throwable e) {
        super(msg, e);
    }
}
