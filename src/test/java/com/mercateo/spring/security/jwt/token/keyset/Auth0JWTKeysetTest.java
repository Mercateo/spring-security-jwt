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
package com.mercateo.spring.security.jwt.token.keyset;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.SigningKeyNotFoundException;

import io.vavr.control.Try;
import lombok.val;

public class Auth0JWTKeysetTest {

    @Test
    public void shouldStoreDomain() {
        val jwtKeyset = new Auth0JWTKeyset("domain");

        assertThat(jwtKeyset.getAuth0Domain()).isEqualTo("domain");
    }

    @Test
    public void shouldReturnFailureForUnknownKeyId() {
        val jwtKeyset = new Auth0JWTKeyset("domain");

        final Try<Jwk> foo = jwtKeyset.getKeysetForId("foo");
        assertThat(foo.isFailure()).isTrue();
        assertThat(foo.getCause()).isInstanceOf(SigningKeyNotFoundException.class);
    }
}