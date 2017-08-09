package com.mercateo.spring.security.jwt.verifier;

import java.util.Stack;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.result.JWTClaim;
import com.mercateo.spring.security.jwt.result.JWTClaims;

import io.vavr.collection.HashSet;
import io.vavr.collection.List;
import io.vavr.collection.Traversable;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class WrappedJWTVerifier {

    public static final String WRAPPED_TOKEN_KEY = "jwt";

    private final JWTSecurityConfig config;

    private final Option<JWTVerifier> verifier;

    public WrappedJWTVerifier(JWTSecurityConfig config) {
        this.config = config;
        this.verifier = Option.ofOptional(config.jwtVerifier());

        verifier.forEach(v -> log.info("use JWT verifier {}", v));
    }

    public JWTClaims collect(String tokenString) {
        List<JWTClaim> claims = List.empty();

        val stack = new Stack<String>();

        stack.push(tokenString);

        int depth = 0;
        int verifiedCount = 0;

        while (!stack.empty()) {
            DecodedJWT token = JWT.decode(stack.pop());

            val verified = verifyToken(token);

            if (verified) {
                verifiedCount++;
            }

            claims = claims.appendAll(extractClaims(token, verified, depth++));

            final Claim wrappedTokenClaim = token.getClaim(WRAPPED_TOKEN_KEY);
            if (!wrappedTokenClaim.isNull()) {
                stack.push(wrappedTokenClaim.asString());
            }
        }

        if (verifiedCount == 0) {
            throw new MissingSignatureException("at least one part of the token should be signed");
        }

        val claimsByName = claims.groupBy(JWTClaim::name);

        val missingRequiredClaims = HashSet.ofAll(config.getRequiredClaims()).removeAll(claimsByName.keySet());

        if (missingRequiredClaims.nonEmpty()) {
            throw new MissingClaimException("missing required claim(s): " + String.join(", ", missingRequiredClaims));
        }

        val claimSet = claimsByName.values().flatMap(Traversable::headOption).toSet();

        return JWTClaims.builder().claims(claimSet).verifiedCount(verifiedCount).token(JWT.decode(tokenString)).build();
    }

    private boolean verifyToken(DecodedJWT token) {
        return verifier
            .map(verifier -> Try
                .of(() -> verifier.verify(token.getToken()))
                .onFailure(e -> log.info("failed verification", e))
                .isSuccess())
            .getOrElse(false);
    }

    private List<JWTClaim> extractClaims(DecodedJWT token, Boolean verified, int i) {
        val requiredClaims = List.ofAll(config.getRequiredClaims());
        val namespaces = List.ofAll(config.getNamespaces()).append("");

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
                .build()));
    }
}
