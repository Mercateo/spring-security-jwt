package com.mercateo.spring.security.jwt.token.exception;

public class TokenException extends RuntimeException {
    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
