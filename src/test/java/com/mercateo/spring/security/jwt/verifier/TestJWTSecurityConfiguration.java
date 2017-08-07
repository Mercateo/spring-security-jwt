package com.mercateo.spring.security.jwt.verifier;

import com.mercateo.spring.security.jwt.JWTAuthenticationProvider;
import com.mercateo.spring.security.jwt.config.ImmutableJWTSecurityConfig;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

import static org.mockito.Mockito.mock;

@Configuration
public class TestJWTSecurityConfiguration {

    @Bean
    public JWTAuthenticationProvider<TestJWTClaims> jwtAuthenticationProvider() {
        return new JWTAuthenticationProvider<>(TestJWTClaims.class, "https://unite.eu/");
    }

    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig.builder().addAnonymousPaths("/admin/app_health").build();
    }

    @Bean
    public JWTKeyset jwtKeyset() {
        return mock(JWTKeyset.class);
    }
}
