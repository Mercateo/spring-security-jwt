package com.mercateo.spring.security.jwt.security;

import com.mercateo.spring.security.jwt.security.JWTPrincipal;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.HashMap;
import io.vavr.collection.List;
import io.vavr.collection.Map;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTPrincipalTest {

    private JWTPrincipal uut;

    static enum Claims {
        FOO_BAR
    }

    @Before
    public void setUp() throws Exception {
        Map<String, JWTClaim> claimsStringHashMap = HashMap.empty();
        claimsStringHashMap = claimsStringHashMap.put("foo_bar", JWTClaim.builder().withName("foo_bar").withValue("<foo_bar>").withIssuer("<issuer>").build());
        uut = new JWTPrincipal(123l, "<username>", "<token>", List.empty(), claimsStringHashMap);
    }

    @Test
    public void shouldTransportId() throws Exception {
        assertThat(uut.getId()).isEqualTo(123l);
    }
}