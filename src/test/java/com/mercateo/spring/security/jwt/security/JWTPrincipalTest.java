package com.mercateo.spring.security.jwt.security;

import com.mercateo.spring.security.jwt.data.ClaimName;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import io.vavr.collection.HashMap;
import io.vavr.collection.List;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTPrincipalTest {

    private JWTPrincipal uut;

    @Before
    public void setUp() throws Exception {
        java.util.Map<String, JWTClaim> claimsStringMap = HashMap.of("foo_bar", JWTClaim
                .builder()
                .name("foo_bar")
                .value("<foo_bar>")
                .issuer("<issuer>")
                .build()).toJavaMap();
        uut = new JWTPrincipal(123l, "<username>", "<token>", List.empty(), claimsStringMap);
    }

    @Test
    public void shouldTransportId() throws Exception {
        assertThat(uut.getId()).isEqualTo(123l);
    }

    @Test
    public void returnsClaimValue() {
        assertThat(uut.getClaim("foo_bar")).get().extracting(JWTClaim::value).isEqualTo("<foo_bar>");
    }

    @Test
    public void returnsClaimIssuer() {
        assertThat(uut.getClaim("foo_bar")).get().extracting(JWTClaim::issuer).isEqualTo("<issuer>");
    }

    @Test
    public void returnsClaimByNameEnum() {
        assertThat(uut.getClaim(Claims.FOO_BAR)).get().extracting(JWTClaim::issuer).isEqualTo("<issuer>");
    }

    enum Claims implements ClaimName {
        FOO_BAR;

        @Override
        public String getValue() {
            return name().toLowerCase();
        }
    }
}