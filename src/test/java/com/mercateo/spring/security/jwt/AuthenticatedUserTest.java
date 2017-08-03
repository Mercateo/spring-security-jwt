package com.mercateo.spring.security.jwt;

import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticatedUserTest {

    private AuthenticatedUser<Claims> uut;

    static enum Claims {
        FOO_BAR
    }

    @Before
    public void setUp() throws Exception {
        final HashMap<Claims, String> claimsStringHashMap = new HashMap<>();
        claimsStringHashMap.put(Claims.FOO_BAR, "<foo_bar>");
        uut = new AuthenticatedUser<>(123l, "<username>", "<token>", Collections.emptyList(), claimsStringHashMap);
    }

    @Test
    public void shouldTransportId() throws Exception {
        assertThat(uut.getId()).isEqualTo(123l);
    }
}