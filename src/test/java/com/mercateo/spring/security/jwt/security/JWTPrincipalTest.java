package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.HashMap;
import io.vavr.collection.List;
import io.vavr.collection.Map;

public class JWTPrincipalTest {

    private JWTPrincipal uut;

    static enum Claims {
        FOO_BAR
    }

    @Before
    public void setUp() throws Exception {
        Map<String, JWTClaim> claimsStringHashMap = HashMap.empty();
        claimsStringHashMap = claimsStringHashMap.put("foo_bar", JWTClaim
            .builder()
            .name("foo_bar")
            .value("<foo_bar>")
            .issuer("<issuer>")
            .build());
        uut = new JWTPrincipal(123l, "<username>", "<token>", List.empty(), claimsStringHashMap);
    }

    @Test
    public void shouldTransportId() throws Exception {
        assertThat(uut.getId()).isEqualTo(123l);
    }
}