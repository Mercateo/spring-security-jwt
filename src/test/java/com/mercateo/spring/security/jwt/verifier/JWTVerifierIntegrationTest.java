package com.mercateo.spring.security.jwt.verifier;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.mercateo.spring.security.jwt.JWTAuthenticationProvider;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { TestJWTSecurityConfiguration.class, JWTSecurityConfiguration.class })
public class JWTVerifierIntegrationTest {

    @Autowired
    private JWTAuthenticationProvider uut;

    @Test
    public void name() throws Exception {

        assertThat((Object) null).isNull();
    }

}
