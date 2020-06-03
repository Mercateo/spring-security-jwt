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

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.RSAKeyProvider;

class AlgorithmFactory {
    private final RSAKeyProvider rsaKeyProvider;

    public AlgorithmFactory(RSAKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public Algorithm createByName(String algorithmName) throws AlgorithmMismatchException {
        switch (algorithmName.toLowerCase()) {
            case "rs256":
                return Algorithm.RSA256(rsaKeyProvider);
            case "rs384":
                return Algorithm.RSA384(rsaKeyProvider);
            case "rs512":
                return Algorithm.RSA512(rsaKeyProvider);
            default:
                throw new AlgorithmMismatchException(
                        "The provided Algorithm has to be RSA.");
        }
    }
}
