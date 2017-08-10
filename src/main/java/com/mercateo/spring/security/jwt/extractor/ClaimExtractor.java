package com.mercateo.spring.security.jwt.extractor;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import io.vavr.collection.List;
import lombok.AllArgsConstructor;
import lombok.val;

@AllArgsConstructor
class ClaimExtractor {

    private final List<String> requiredClaims;

    private final List<String> namespaces;

    List<JWTClaim> extractClaims(DecodedJWT token, Boolean verified, int depth) {
        val tokenIssuer = token.getIssuer();
        return requiredClaims.flatMap(claimName -> namespaces
                .map(namespace -> namespace + claimName)
                .map(token::getClaim)
                .find(claim -> !claim.isNull())
                .map(claim -> (JWTClaim) JWTClaim
                        .builder()
                        .name(claimName)
                        .value(claim.asString())
                        .verified(verified)
                        .issuer(tokenIssuer)
                        .depth(depth)
                        .build()));
    }
}
