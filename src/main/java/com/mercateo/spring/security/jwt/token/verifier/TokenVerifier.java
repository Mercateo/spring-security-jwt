/**
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

import static java.lang.Boolean.FALSE;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;

import io.vavr.Function2;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.AllArgsConstructor;
import lombok.val;

@AllArgsConstructor
public class TokenVerifier {

    private final Option<JWTVerifier> verifier;

    public boolean verifyToken(DecodedJWT token) {
        val verifyToken = Function2.of(this::verify).apply(token);

        return verifier //
            .filter(ignore -> !"none".equals(token.getAlgorithm()))
            .map(verifyToken)
            .getOrElse(FALSE);
    }

    private boolean verify(DecodedJWT token, JWTVerifier verifier) {
        return Try
            .of(() -> verifier.verify(token.getToken())) //
            .onFailure(e -> {
                throw new InvalidTokenException("could not verify token", e);
            })
            .isSuccess();
    }
}
