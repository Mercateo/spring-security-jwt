package com.mercateo.spring.security.jwt.token.extractor;

import java.util.Stack;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import com.mercateo.spring.security.jwt.token.verifier.TokenVerifier;
import io.vavr.collection.List;
import io.vavr.collection.Set;
import lombok.val;

import static java.util.Objects.requireNonNull;

class HierarchicalClaimsExtractor {

    private final TokenProcessor tokenProcessor;

    private final TokenVerifier verifier;

    private final Set<String> claims;

    private final Set<String> namespaces;

    private int depth;

    private int verifiedTokenCount;

    HierarchicalClaimsExtractor(TokenProcessor tokenProcessor, TokenVerifier verifier, Set<String> claims,
            Set<String> namespaces) {
        this.tokenProcessor = tokenProcessor;
        this.verifier = verifier;
        this.claims = claims;
        this.namespaces = namespaces;

        depth = 0;
        verifiedTokenCount = 0;
    }

    List<JWTClaim> extractClaims(String tokenString) {
        List<JWTClaim> claims = List.empty();

        val stack = new Stack<String>();
        stack.push(tokenString);

        while (!stack.empty()) {
            val token = tokenProcessor.getNextToken(stack.pop());
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
                .withName(claimName)
                .withValue(claim.asString())
                .withVerified(verified)
                .withIssuer(requireNonNull(token.getIssuer(), "token issuer (iss) not found"))
                .withDepth(depth)
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
