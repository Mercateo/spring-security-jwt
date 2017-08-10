package com.mercateo.spring.security.jwt.token.extractor;

import java.util.Optional;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;
import com.mercateo.spring.security.jwt.token.result.JWTClaims;

import io.vavr.collection.List;
import io.vavr.collection.Map;

class HierarchicalClaimsWrapper {

    Map<String, JWTClaim> wrapHierarchicalClaims(List<JWTClaim> claims) {
        return claims.groupBy(JWTClaim::name).mapValues(this::wrapGroupedClaims);
    }

    private JWTClaim wrapGroupedClaims(List<JWTClaim> claims) {
        final List<JWTClaim> reverse = claims.reverse();

        Optional<JWTClaim> innerClaim = Optional.empty();

        for (JWTClaim jwtClaim : reverse) {
            innerClaim = Optional.of(JWTClaim.builder().from(jwtClaim).innerClaim(innerClaim).build());
        }

        // noinspection ConstantConditions
        return innerClaim.get();
    }
}
