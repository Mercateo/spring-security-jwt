package com.mercateo.spring.security.jwt.token.extractor;

import com.auth0.jwt.JWT;
import com.mercateo.spring.security.jwt.security.config.JWTSecurityConfig;
import com.mercateo.spring.security.jwt.token.result.JWTClaims;

import io.vavr.collection.List;
import io.vavr.control.Option;
import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HierarchicalJWTClaimsExtractor {

    public static final String WRAPPED_TOKEN_KEY = "jwt";

    private final TokenProcessor tokenProcessor;

    private final TokenVerifier verifier;

    private final HierarchicalClaimsWrapper collector;

    private final ClaimsValidator claimsValidator;

    private final List<String> requiredClaims;

    private final List<String> namespaces;

    public HierarchicalJWTClaimsExtractor(JWTSecurityConfig config) {
        this.tokenProcessor = new TokenProcessor();
        this.verifier = new TokenVerifier(Option.ofOptional(config.jwtVerifier()));
        requiredClaims = List.ofAll(config.getRequiredClaims());
        namespaces = List.ofAll(config.getNamespaces()).append("");
        this.claimsValidator = new ClaimsValidator(requiredClaims);
        this.collector = new HierarchicalClaimsWrapper();

        config.jwtVerifier().ifPresent(v -> log.info("use JWT verifier {}", v));
    }

    public JWTClaims extractClaims(String tokenString) {
        val extractor = new HierarchicalClaimsExtractor(tokenProcessor, verifier, requiredClaims, namespaces);

        val claims = extractor.extractClaims(tokenString);

        claimsValidator.ensureAtLeastOneValidatedToken(extractor.getVerifiedTokenCount());
        claimsValidator.ensurePresenceOfRequiredClaims(claims);

        return JWTClaims
            .builder()
            .claims(collector.wrapHierarchicalClaims(claims))
            .verifiedCount(extractor.getVerifiedTokenCount())
            .token(JWT.decode(tokenString))
            .build();
    }

}
