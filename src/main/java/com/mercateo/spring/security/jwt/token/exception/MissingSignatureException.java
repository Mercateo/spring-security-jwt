package com.mercateo.spring.security.jwt.token.exception;

public class MissingSignatureException extends TokenException {
    public MissingSignatureException(String message) {
        super(message);
    }
}
