package com.mercateo.spring.security.jwt.extractor;

import java.util.Optional;

import com.mercateo.spring.security.jwt.result.JWTClaim;

import io.vavr.collection.List;
import io.vavr.collection.Map;

class HierarchicalClaimCollector {
    Map<String, JWTClaim> collectHierarchicalClaims(List<JWTClaim> claims) {
        return claims.groupBy(JWTClaim::name).mapValues(this::wrapGroupdClaims);
    }

    private JWTClaim wrapGroupdClaims(List<JWTClaim> claims) {
        final List<JWTClaim> reverse = claims.reverse();

        Optional<JWTClaim> innerClaim = Optional.empty();

        List<JWTClaim> wrappedClaims = List.empty();
        for (JWTClaim jwtClaim : reverse) {
            innerClaim = Optional.of(JWTClaim.builder().from(jwtClaim).innerClaim(innerClaim).build());
        }

        // noinspection ConstantConditions
        return innerClaim.get();
    }
}
