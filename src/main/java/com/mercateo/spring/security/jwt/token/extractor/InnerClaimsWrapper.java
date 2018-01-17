package com.mercateo.spring.security.jwt.token.extractor;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.List;
import io.vavr.collection.Map;
import io.vavr.control.Option;

class InnerClaimsWrapper {

    Map<String, JWTClaim> wrapInnerClaims(List<JWTClaim> claims) {
        return claims.groupBy(JWTClaim::name).mapValues(this::wrapGroupedClaims);
    }

    private JWTClaim wrapGroupedClaims(List<JWTClaim> claims) {
        final List<JWTClaim> reverse = claims.reverse();

        Option<JWTClaim> innerClaim = Option.none();

        for (JWTClaim jwtClaim : reverse) {
            innerClaim = Option.some(JWTClaim //
                .builder()
                .from(jwtClaim)
                .innerClaim(innerClaim)
                .build());
        }

        // noinspection ConstantConditions
        return innerClaim.get();
    }
}
