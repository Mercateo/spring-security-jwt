package com.mercateo.spring.security.jwt.token.extractor;

import java.util.Stack;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;
import com.mercateo.spring.security.jwt.token.result.JWTClaims;

import io.vavr.collection.HashSet;
import io.vavr.collection.List;
import io.vavr.control.Option;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class WrappedJWTExtractor {

    public static final String WRAPPED_TOKEN_KEY = "jwt";

    private final JWTSecurityConfig config;

    private final TokenVerifier verifier;

    private final ClaimExtractor extractor;

    private final HierarchicalClaimCollector collector;

    public WrappedJWTExtractor(JWTSecurityConfig config) {
        this.config = config;
        this.verifier = new TokenVerifier(Option.ofOptional(config.jwtVerifier()));
        this.extractor = new ClaimExtractor(List.ofAll(config.getRequiredClaims()), List
            .ofAll(config.getNamespaces())
            .append(""));
        this.collector = new HierarchicalClaimCollector();

        config.jwtVerifier().ifPresent(v -> log.info("use JWT verifier {}", v));
    }

    public JWTClaims extract(String tokenString) {
        List<JWTClaim> claims = List.empty();

        val stack = new Stack<String>();

        stack.push(tokenString);

        int depth = 0;
        int verifiedTokenCount = 0;

        while (!stack.empty()) {
            final String tokenString2 = stack.pop();
            DecodedJWT token = JWT.decode(tokenString2);

            val verified = verifier.verifyToken(token);
            if (verified) {
                verifiedTokenCount++;
            }

            val tokenClaims = extractor.extractClaims(token, verified, depth++);
            claims = claims.appendAll(tokenClaims);

            Option
                .of(token.getClaim(WRAPPED_TOKEN_KEY)) //
                .filter(claim -> !claim.isNull())
                .map(Claim::asString)
                .forEach(stack::push);
        }

        ensureAtLeastOneValidatedToken(verifiedTokenCount);

        ensurePresenceOfRequiredClaims(claims);

        val hierarchicalClaims = collector.collectHierarchicalClaims(claims);

        return JWTClaims
            .builder()
            .claims(hierarchicalClaims)
            .verifiedCount(verifiedTokenCount)
            .token(JWT.decode(tokenString))
            .build();
    }

    private void ensureAtLeastOneValidatedToken(int verifiedCount) {
        if (verifiedCount == 0) {
            throw new MissingSignatureException("at least one part of the token should be signed");
        }
    }

    private void ensurePresenceOfRequiredClaims(List<JWTClaim> claims) {
        val existingClaimNames = claims.groupBy(JWTClaim::name).keySet();
        val requiredClaimNames = HashSet.ofAll(config.getRequiredClaims());

        val missingRequiredClaimNames = requiredClaimNames.removeAll(existingClaimNames);

        if (missingRequiredClaimNames.nonEmpty()) {
            throw new MissingClaimException("missing required claim(s): " + String.join(", ",
                    missingRequiredClaimNames));
        }
    }

}
