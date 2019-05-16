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
package com.mercateo.spring.security.jwt.token.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.List;

public class InnerClaimsWrapperTest {

    private InnerClaimsWrapper uut;

    @Before
    public void setUp() {
        uut = new InnerClaimsWrapper();
    }

    @Test
    public void given3Claims_whenWrapInnerClaims_thenMapWith3Keys() {
        final JWTClaim jwtClaim1 = JWTClaim.builder().name("jwtClaim1").value("value1").issuer("iss").build();
        final JWTClaim jwtClaim2 = JWTClaim.builder().name("jwtClaim2").value("value2").issuer("iss").build();
        final JWTClaim jwtClaim3 = JWTClaim.builder().name("jwtClaim3").value("value3").issuer("iss").build();

        final Map<String, JWTClaim> result = uut.wrapInnerClaims(List.of(jwtClaim1, jwtClaim2, jwtClaim3));
        assertThat(result).isNotNull().isNotEmpty().hasSize(3);
        assertThat(result).containsOnlyKeys("jwtClaim1", "jwtClaim2", "jwtClaim3");
    }

    @Test
    public void given2IdenticalClaims_whenWrapInnerClaims_thenMapWith1Key() {
        final JWTClaim jwtClaim1 = JWTClaim.builder().name("jwtClaim1").value("value1").issuer("iss").build();

        final Map<String, JWTClaim> result = uut.wrapInnerClaims(List.of(jwtClaim1, jwtClaim1));
        assertThat(result).isNotNull().isNotEmpty().hasSize(1);
        assertThat(result).containsOnlyKeys("jwtClaim1");
    }

    @Test
    public void givenNoClaims_whenWrapInnerClaims_thenEmptyMap() {
        final Map<String, JWTClaim> result = uut.wrapInnerClaims(List.empty());
        assertThat(result).isNotNull().isEmpty();
    }

    @Test(expected = NullPointerException.class)
    public void givenNull_whenWrapInnerClaims_then() {
        uut.wrapInnerClaims(null);
    }
}
