package com.mercateo.spring.security.jwt.token.config;

import com.mercateo.immutables.DataClass;
import org.immutables.value.Value;

@Value.Immutable
@DataClass
public interface JWTConfigData extends JWTConfig {
    static ImmutableJWTConfigData.Builder builder() {
        return ImmutableJWTConfigData.builder();
    }
}
