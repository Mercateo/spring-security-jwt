package com.mercateo.spring.security.jwt.token.exception;

public class MissingClaimException extends TokenException {
    public MissingClaimException(String message) {
        super(message);
    }
}
