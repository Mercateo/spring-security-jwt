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
package com.mercateo.spring.security.jwt.token.config;

import org.immutables.value.Value;

import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifier;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifierFactory;

import io.vavr.collection.Set;
import io.vavr.control.Option;

public interface JWTConfig {

    /**
     * @return The default window in seconds in which the Not Before, Issued At and
     *         Expires At Claims will still be valid.
     *
     *         Setting a specific leeway value on a given Claim will override this
     *         value for that Claim.
     */
    @Value.Default
    default int getTokenLeeway() {
        return 0;
    }

    /**
     * @return required Audience ("aud") claims
     */
    Set<String> getTokenAudiences();

    /**
     * @return set of required claims
     */
    Set<String> getRequiredClaims();

    /**
     * @return set of claims which should be processed if they exist
     */
    Set<String> getOptionalClaims();

    /**
     * @return {@link JWTKeyset} to be used for token verification
     */
    Option<JWTKeyset> jwtKeyset();

    /**
     * @return {@link JWTVerifier} for given {@link JWTKeyset} to be used for token
     *         verification
     */
    @Value.Derived
    default Option<JWTVerifier> jwtVerifier() {
        return jwtKeyset().map(jwks -> new JWTVerifierFactory(jwks, this)).map(JWTVerifierFactory::create);
    }
}
