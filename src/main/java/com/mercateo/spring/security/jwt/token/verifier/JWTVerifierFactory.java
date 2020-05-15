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

import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

import lombok.extern.slf4j.Slf4j;
import lombok.val;

@Slf4j
public class JWTVerifierFactory {
    private final RSAKeyProviderFactory keyProviderFactory;

    private final JWTConfig jwtConfig;

    public JWTVerifierFactory(JWTKeyset jwtKeyset, JWTConfig jwtConfig) {
        this.keyProviderFactory = new RSAKeyProviderFactory(jwtKeyset);
        this.jwtConfig = jwtConfig;
    }

    public JWTVerifier create() {
        val verification = JWTVerifier.init(keyProviderFactory.create());

        final int tokenLeeway = jwtConfig.getTokenLeeway();
        verification.acceptLeeway(tokenLeeway);

        val tokenAudiences = jwtConfig.getTokenAudiences();
        if (tokenAudiences.nonEmpty()) {
            verification.withAudience(tokenAudiences.toJavaArray(String[]::new));
        }

        return verification.build();
    }
}
