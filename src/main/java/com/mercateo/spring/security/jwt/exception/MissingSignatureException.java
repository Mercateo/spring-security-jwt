package com.mercateo.spring.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class MissingSignatureException extends AuthenticationException {
    public MissingSignatureException(String msg) {
        super(msg);
    }
}
