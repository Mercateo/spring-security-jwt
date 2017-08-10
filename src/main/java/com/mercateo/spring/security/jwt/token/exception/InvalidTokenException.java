package com.mercateo.spring.security.jwt.token.exception;

public class InvalidTokenException extends TokenException {
    public InvalidTokenException(String msg, Throwable e) {
        super(msg, e);
    }
}
