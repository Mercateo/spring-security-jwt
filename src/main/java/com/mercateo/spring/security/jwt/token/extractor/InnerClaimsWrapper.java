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

import java.util.Map;
import java.util.Optional;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.List;

class InnerClaimsWrapper {

    Map<String, JWTClaim> wrapInnerClaims(List<JWTClaim> claims) {
        return claims.groupBy(JWTClaim::name).mapValues(this::wrapGroupedClaims).toJavaMap();
    }

    private JWTClaim wrapGroupedClaims(List<JWTClaim> claims) {
        final List<JWTClaim> reverse = claims.reverse();
        JWTClaim innerClaim = null;
        for (JWTClaim jwtClaim : reverse) {
            innerClaim = buildJwtClaim(jwtClaim, innerClaim);
        }
        return innerClaim;
    }

    private JWTClaim buildJwtClaim(final JWTClaim jwtClaim, final JWTClaim innerClaim) {
        return JWTClaim //
                .builder()
                .from(jwtClaim)
                .innerClaim(Optional.ofNullable(innerClaim))
                .build();
    }
}
