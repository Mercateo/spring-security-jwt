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

import static java.util.Objects.requireNonNull;

import java.util.Stack;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.verifier.TokenVerifier;

import io.vavr.collection.List;
import io.vavr.collection.Set;
import lombok.val;

class HierarchicalClaimsExtractor {

    private final TokenProcessor tokenProcessor;

    private final TokenVerifier verifier;

    private final Set<String> claims;

    private final Set<String> namespaces;

    private final ClaimExtractor claimExtractor;

    private int depth;

    private int verifiedTokenCount;

    HierarchicalClaimsExtractor(TokenProcessor tokenProcessor, TokenVerifier verifier, Set<String> claims,
            Set<String> namespaces, ClaimExtractor claimExtractor) {
        this.tokenProcessor = tokenProcessor;
        this.verifier = verifier;
        this.claims = claims;
        this.namespaces = namespaces;
        this.claimExtractor = claimExtractor;

        depth = 0;
        verifiedTokenCount = 0;
    }

    List<JWTClaim> extractClaims(String tokenString) {
        List<JWTClaim> claims = List.empty();

        val stack = new Stack<String>();
        stack.push(tokenString);

        while (!stack.empty()) {
            val token = tokenProcessor.decodeToken(stack.pop());
            tokenProcessor.memoizePossiblyWrappedToken(token, stack::push);

            boolean verified = verifyToken(token);
            claims = claims.appendAll(extractClaims(token, verified));

            depth++;
        }

        return claims;
    }

    private List<JWTClaim> extractClaims(DecodedJWT token, boolean verified) {

        return claims.toList().flatMap(claimName -> namespaces
            .map(namespace -> namespace + claimName)
            .map(token::getClaim)
            .find(claim -> !claim.isNull())
            .map(claim -> (JWTClaim) JWTClaim
                .builder()
                .name(claimName)
                .value(claimExtractor.extract(claim))
                .verified(verified)
                .issuer(requireNonNull(token.getIssuer(), "token issuer (iss) not found"))
                .depth(depth)
                .build()));
    }

    private boolean verifyToken(DecodedJWT token) {
        val verified = verifier.verifyToken(token);

        if (verified) {
            verifiedTokenCount++;
        }
        return verified;
    }

    int getVerifiedTokenCount() {
        return verifiedTokenCount;
    }
}
