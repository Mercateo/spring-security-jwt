package com.mercateo.spring.security.jwt.security.config;

import org.immutables.value.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.mercateo.immutables.DataClass;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;

import io.vavr.collection.Set;
import io.vavr.control.Option;

@Value.Immutable
@DataClass
public interface JWTSecurityConfig extends JWTConfig {

    /**
     * @return Paths with anonymous access
     */
    Set<String> anonymousPaths();

    /**
     * @return {@link HttpMethod} with anynomous access
     */
    Set<HttpMethod> anonymousMethods();

    Option<AuthenticationFailureHandler> authenticationFailureHandler();

    static ImmutableJWTSecurityConfig.Builder builder() {
        return ImmutableJWTSecurityConfig.builder();
    }
}
