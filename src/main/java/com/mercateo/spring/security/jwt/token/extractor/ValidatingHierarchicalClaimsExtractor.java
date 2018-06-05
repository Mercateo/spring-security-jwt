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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.verifier.TokenVerifier;

import io.vavr.collection.List;
import io.vavr.collection.Set;
import io.vavr.control.Option;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidatingHierarchicalClaimsExtractor {

    public static final String WRAPPED_TOKEN_KEY = "jwt";

    public static final List<String> AUTHORIZATION_CLAIMS = List.of("scope", "authorization");

    private final TokenProcessor tokenProcessor;

    private final TokenVerifier verifier;

    private final InnerClaimsWrapper collector;

    private final ClaimsValidator claimsValidator;

    private final Set<String> claims;

    private final Set<String> requiredClaims;

    private final Set<String> namespaces;

    private final Option<JWTVerifier> jwtVerifier;

    public ValidatingHierarchicalClaimsExtractor(JWTConfig config) {
        this.tokenProcessor = new TokenProcessor();
        jwtVerifier = config.jwtVerifier();
        this.verifier = new TokenVerifier(jwtVerifier);
        requiredClaims = config.getRequiredClaims();
        claims = config.getOptionalClaims().addAll(AUTHORIZATION_CLAIMS).addAll(requiredClaims);
        namespaces = config.getNamespaces().add("");
        this.claimsValidator = new ClaimsValidator(requiredClaims);
        this.collector = new InnerClaimsWrapper();

        config.jwtVerifier().forEach(v -> log.info("use JWT verifier {}", v));
    }

    public JWTClaims extractClaims(String tokenString) {
        val extractor = new HierarchicalClaimsExtractor(tokenProcessor, verifier, claims, namespaces);

        val claims = extractor.extractClaims(tokenString);

        if (jwtVerifier.isDefined()) {
            claimsValidator.ensureAtLeastOneVerifiedToken(extractor.getVerifiedTokenCount());
        }
        claimsValidator.ensurePresenceOfRequiredClaims(claims);

        return JWTClaims
            .builder()
            .claims(collector.wrapInnerClaims(claims))
            .verifiedCount(extractor.getVerifiedTokenCount())
            .token(JWT.decode(tokenString))
            .build();
    }

    public boolean hasJWTVerifier() {
        return jwtVerifier.isDefined();
    }

}
