package com.mercateo.spring.security.jwt.verifier;

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes={TestJWTSecurityConfiguration.class, JWTSecurityConfiguration.class})
public class JWTVerifierIntegrationTest {

    private Optional<JWTVerifier> verifier;


    @Test
    public void name() throws Exception {
        assertThat(verifier).isNotNull();
    }

    @Autowired
    public void setVerifier(Optional<JWTVerifier> verifier) {
        this.verifier = verifier;
    }
}
