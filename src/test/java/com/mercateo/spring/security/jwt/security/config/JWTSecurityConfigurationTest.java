package com.mercateo.spring.security.jwt.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { JWTSecurityConfigurationTest.TestConfiguration.class,
        JWTSecurityConfiguration.class })
public class JWTSecurityConfigurationTest {

    @Autowired
    ValidatingHierarchicalClaimsExtractor extractor;

    @Test
    public void injectsJWTVerifier() throws Exception {
        assertThat(extractor.hasJWTVerifier()).isTrue();
    }

    @Configuration
    static class TestConfiguration {
        @Bean
        public JWTSecurityConfig securityConfig() {
            return JWTSecurityConfig.builder().jwtKeyset(mock(JWTKeyset.class)).build();
        }
    }
}