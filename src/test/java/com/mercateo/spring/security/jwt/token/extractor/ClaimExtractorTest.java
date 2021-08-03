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
import static org.assertj.core.api.Assertions.entry;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.val;

public class ClaimExtractorTest {

    private ClaimExtractor uut;

    private DecodedJWT jwt;

    @Before
    public void setUp() throws Exception {
        uut = new ClaimExtractor();

        final JWTCreator.Builder builder = JWT
            .create()
            .withClaim("int", 123)
            .withClaim("double", 3.1415)
            .withClaim("bool", true)
            .withClaim("string", "text")
            .withClaim("long", Long.MAX_VALUE)
            .withArrayClaim("stringArray", new String[] { "foo", "bar", "baz" });

        final Method addClaim = JWTCreator.Builder.class.getDeclaredMethod("addClaim", String.class, Object.class);
        addClaim.setAccessible(true);

        final HashMap<String, Object> objectClaim = new HashMap<>();
        objectClaim.put("foo", 1.2);
        objectClaim.put("bar", "test");
        addClaim.invoke(builder, "object", objectClaim);

        jwt = JWT.decode(builder.sign(Algorithm.none()));
    }

    @Test
    public void extractsString() {
        val result = uut.extract(jwt.getClaim("string"));

        assertThat(result).isEqualTo("text");
    }

    @Test
    public void extractsInteger() {
        val result = uut.extract(jwt.getClaim("int"));

        assertThat(result).isEqualTo(123);
    }

    @Test
    public void extractsLong() {
        val result = uut.extract(jwt.getClaim("long"));

        assertThat(result).isEqualTo(Long.MAX_VALUE);
    }

    @Test
    public void extractsDouble() {
        val result = uut.extract(jwt.getClaim("double"));

        assertThat(result).isEqualTo(3.1415);
    }

    @Test
    public void extractsBool() {
        val result = uut.extract(jwt.getClaim("bool"));

        assertThat(result).isEqualTo(true);
    }

    @Test
    public void extractsArray() {
        val result = uut.extract(jwt.getClaim("stringArray"));

        assertThat((Object[]) result).containsExactly("foo", "bar", "baz");
    }

    @Test
    public void extractsObject() {
        val result = uut.extract(jwt.getClaim("object"));

        assertThat((Map<String, Object>) result).isNotNull().isNotEmpty()
                .contains(entry("foo", 1.2), entry("bar", "test"));
    }

    @Test
    public void extractsUnknownClaimAsNull() {
        val result = uut.extract(jwt.getClaim("unknown"));

        assertThat(result).isNull();
    }
}