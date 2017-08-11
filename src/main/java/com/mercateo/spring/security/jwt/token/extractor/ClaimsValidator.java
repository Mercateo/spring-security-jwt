package com.mercateo.spring.security.jwt.token.extractor;

import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;

import io.vavr.collection.HashSet;
import io.vavr.collection.List;
import lombok.val;

class ClaimsValidator {
    private final List<String> requiredClaims;

    ClaimsValidator(List<String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }

    void ensureAtLeastOneValidatedToken(int verifiedCount) {
        if (verifiedCount == 0) {
            throw new MissingSignatureException("at least one part of the token should be signed");
        }
    }

    void ensurePresenceOfRequiredClaims(List<JWTClaim> claims) {
        val existingClaimNames = claims.groupBy(JWTClaim::name).keySet();
        val requiredClaimNames = HashSet.ofAll(requiredClaims);

        val missingRequiredClaimNames = requiredClaimNames.removeAll(existingClaimNames);

        if (missingRequiredClaimNames.nonEmpty()) {
            throw new MissingClaimException("missing required claim(s): " + String.join(", ",
                    missingRequiredClaimNames));
        }
    }
}
