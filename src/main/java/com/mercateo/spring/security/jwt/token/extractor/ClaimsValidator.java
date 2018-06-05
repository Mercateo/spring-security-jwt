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
package com.mercateo.spring.security.jwt.token.extractor;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;

import io.vavr.Value;
import io.vavr.collection.HashSet;
import io.vavr.collection.List;
import lombok.val;

class ClaimsValidator {
    private final Value<String> claims;

    ClaimsValidator(Value<String> claims) {
        this.claims = claims;
    }

    void ensureAtLeastOneVerifiedToken(int verifiedCount) {
        if (verifiedCount == 0) {
            throw new MissingSignatureException("at least one part of the token should be signed");
        }
    }

    void ensurePresenceOfRequiredClaims(List<JWTClaim> claims) {
        val existingClaimNames = claims.groupBy(JWTClaim::name).keySet();
        val requiredClaimNames = HashSet.ofAll(this.claims);

        val missingRequiredClaimNames = requiredClaimNames.removeAll(existingClaimNames);

        if (missingRequiredClaimNames.nonEmpty()) {
            throw new MissingClaimException("missing required claim(s): " + String.join(", ",
                    missingRequiredClaimNames));
        }
    }
}
