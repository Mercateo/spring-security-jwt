package com.mercateo.spring.security.jwt.verifier;

import static org.mockito.Mockito.mock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.mercateo.spring.security.jwt.config.JWTAuthenticationConfig;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfig;

@Configuration
public class TestJWTSecurityConfiguration {

    @Bean
    public JWTAuthenticationConfig jwtAuthenticationConfig() {
        return JWTAuthenticationConfig
            .builder()
            .addNamespaces("https://test.org/")
            .addRequiredClaims("scope", "foo")
            .build();
    }

    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig
            .builder()
            .addAnonymousPaths("/admin/app_health")
            .jwtKeyset(mock(JWTKeyset.class))
            .build();
    }
}
