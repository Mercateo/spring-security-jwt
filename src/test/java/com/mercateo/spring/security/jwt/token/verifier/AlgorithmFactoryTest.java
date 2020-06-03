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
package com.mercateo.spring.security.jwt.token.verifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import io.vavr.control.Try;

public class AlgorithmFactoryTest {

    private AlgorithmFactory uut;

    @Before
    public void setUp() {
        final JWKProvider jwkProvider = new JWKProvider();
        String keyId = "4711";
        final Jwk jwk = jwkProvider.create(keyId);
        JWTKeyset jwks = mock(JWTKeyset.class);
        when(jwks.getKeysetForId(keyId)).thenReturn(Try.success(jwk));
        assertThat(jwks.getKeysetForId(keyId)).isNotNull();
        RSAKeyProviderFactory keyProviderFactory = new RSAKeyProviderFactory(jwks);
        uut = new AlgorithmFactory(keyProviderFactory.create());
    }

    @Test
    public void createsRSA256Algorithm() {
        Algorithm algo1 = uut.createByName("RS256");
        assertEquals("RS256", algo1.getName());
    }

    @Test
    public void createRSA384Algorithm() {
        Algorithm algo2 = uut.createByName("RS384");
        assertEquals("RS384", algo2.getName());
    }

    @Test
    public void createRSA512Algorithm() {
        Algorithm algo3 = uut.createByName("RS512");
        assertEquals("RS512", algo3.getName());
    }

    @Test
    public void failsCreatingUnknownAlgorithm() {
        assertThatThrownBy(() -> uut.createByName("foo")).isInstanceOf(AlgorithmMismatchException.class);
    }
}
