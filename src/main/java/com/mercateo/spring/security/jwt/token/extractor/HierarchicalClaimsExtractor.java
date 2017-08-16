package com.mercateo.spring.security.jwt.token.extractor;

import java.util.Stack;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.Value;
import io.vavr.collection.List;
import io.vavr.collection.Set;
import lombok.val;

class HierarchicalClaimsExtractor {

    private final TokenProcessor tokenProcessor;

    private final TokenVerifier verifier;

    private final List<String> claims;

    private final List<String> namespaces;

    private int depth;

    private int verifiedTokenCount;

    HierarchicalClaimsExtractor(TokenProcessor tokenProcessor, TokenVerifier verifier, Value<String> claims,
            List<String> namespaces) {
        this.tokenProcessor = tokenProcessor;
        this.verifier = verifier;
        this.claims = claims.toList();
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
                .name(claimName)
                .value(claim.asString())
                .verified(verified)
                .issuer(token.getIssuer())
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
