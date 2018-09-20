package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;

import com.mercateo.spring.security.jwt.data.ClaimName;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.HashMap;
import io.vavr.collection.List;
import io.vavr.collection.Map;

public class JWTPrincipalTest {

    private JWTPrincipal uut;

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

    @Test
    public void returnsClaimValue() {
        assertThat(uut.getClaim("foo_bar")).extracting(JWTClaim::value).containsExactly("<foo_bar>");
    }

    @Test
    public void returnsClaimIssuer() {
        assertThat(uut.getClaim("foo_bar")).extracting(JWTClaim::issuer).containsExactly("<issuer>");
    }

    @Test
    public void returnsClaimByNameEnum() {
        assertThat(uut.getClaim(Claims.FOO_BAR)).extracting(JWTClaim::issuer).containsExactly("<issuer>");
    }

    enum Claims implements ClaimName {
        FOO_BAR;

        @Override
        public String getValue() {
            return name().toLowerCase();
        }
    }
}