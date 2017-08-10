package com.mercateo.spring.security.jwt;

import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTAuthenticationTokenTest {

    private JWTAuthenticationToken uut;

    @Before
    public void setUp() throws Exception {
        uut = new JWTAuthenticationToken("<token>");
    }

    @Test
    public void shouldContainToken() throws Exception {
        assertThat(uut.getToken()).isEqualTo("<token>");
    }
}