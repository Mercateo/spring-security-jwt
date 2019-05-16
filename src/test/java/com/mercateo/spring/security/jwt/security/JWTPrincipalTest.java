/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;

import com.mercateo.spring.security.jwt.data.ClaimName;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.HashMap;
import io.vavr.collection.List;

public class JWTPrincipalTest {

    private JWTPrincipal uut;

    @Before
    public void setUp()  {
        java.util.Map<String, JWTClaim> claimsStringMap = HashMap.of("foo_bar", JWTClaim
                .builder()
                .name("foo_bar")
                .value("<foo_bar>")
                .issuer("<issuer>")
                .build()).toJavaMap();
        uut = new JWTPrincipal(123L, "<username>", "<token>", List.empty(), claimsStringMap);
    }

    @Test
    public void shouldTransportId() {
        assertThat(uut.getId()).isEqualTo(123L);
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
