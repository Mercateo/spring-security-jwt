package com.mercateo.spring.security.jwt;

import com.mercateo.spring.security.jwt.result.JWTClaim;
import io.vavr.collection.List;
import io.vavr.collection.Map;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticatedTest {

    private Authenticated uut;

    static enum Claims {
        FOO_BAR
    }

    @Before
    public void setUp() throws Exception {
        Map<String, String> claimsStringHashMap = io.vavr.collection.HashMap.empty();
        claimsStringHashMap = claimsStringHashMap.put("foo_bar", "<foo_bar>");
        uut = new Authenticated(123l, "<username>", "<token>", List.empty(), claimsStringHashMap);
    }

    @Test
    public void shouldTransportId() throws Exception {
        assertThat(uut.getId()).isEqualTo(123l);
    }
}