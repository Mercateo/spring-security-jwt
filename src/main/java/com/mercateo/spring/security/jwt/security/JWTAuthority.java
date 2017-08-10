package com.mercateo.spring.security.jwt.security;

import org.immutables.value.Value;
import org.springframework.security.core.GrantedAuthority;

@Value.Immutable
public interface JWTAuthority extends GrantedAuthority {

    static ImmutableJWTAuthority.Builder builder() {
        return ImmutableJWTAuthority.builder();
    }

}
