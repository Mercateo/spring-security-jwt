/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.token.verifier;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.val;

/**
 * The JWTVerifier class holds the verify method to assert that a given Token
 * has not only a proper JWT format, but also it's signature matches.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTVerifier {
    private final Map<String, Object> claims;
    private final Algorithm algorithm;
    private final Clock clock;

    JWTVerifier(Algorithm algorithm, Map<String, Object> claims, Clock clock) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
        this.clock = clock;
    }

    /**
     * Initialize a JWTVerifier instance using the given Algorithm.
     *
     * @param algorithm
     *            the Algorithm to use on the JWT verification.
     * @return a JWTVerifier.Verification instance to configure.
     * @throws IllegalArgumentException
     *             if the provided algorithm is null.
     */
    public static BaseVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new BaseVerification(algorithm);
    }

    /**
     * Perform the verification against the given Token, using any previous
     * configured options.
     *
     * @param token
     *            to verify.
     * @return a verified and decoded JWT.
     * @throws AlgorithmMismatchException
     *             if the algorithm stated in the token's header it's not equal to
     *             the one defined in the {@link JWTVerifier}.
     * @throws SignatureVerificationException
     *             if the signature is invalid.
     * @throws TokenExpiredException
     *             if the token has expired.
     * @throws InvalidClaimException
     *             if a claim contained a different value than the expected one.
     */
    public DecodedJWT verify(String token) throws JWTVerificationException {
        DecodedJWT jwt = JWT.decode(token);
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, claims);
        return jwt;
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException(
                    "The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException,
            InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            switch (entry.getKey()) {
            case PublicClaims.AUDIENCE:
                // noinspection unchecked
                assertValidAudienceClaim(jwt.getAudience(), (Set<String>) entry.getValue());
                break;
            case PublicClaims.EXPIRES_AT:
                assertValidDateClaim(jwt.getExpiresAt(), (Long) entry.getValue(), true);
                break;
            case PublicClaims.NOT_BEFORE:
                assertValidDateClaim(jwt.getNotBefore(), (Long) entry.getValue(), false);
                break;
            default:
                assertValidClaim(jwt.getClaim(entry.getKey()), entry.getKey(), entry.getValue());
                break;
            }
        }
    }

    private void assertValidClaim(Claim claim, String claimName, Object value) {
        boolean isValid = false;
        if (value instanceof String) {
            isValid = value.equals(claim.asString());
        } else if (value instanceof Integer) {
            isValid = value.equals(claim.asInt());
        } else if (value instanceof Long) {
            isValid = value.equals(claim.asLong());
        } else if (value instanceof Boolean) {
            isValid = value.equals(claim.asBoolean());
        } else if (value instanceof Double) {
            isValid = value.equals(claim.asDouble());
        } else if (value instanceof Date) {
            isValid = value.equals(claim.asDate());
        } else if (value instanceof Object[]) {
            List<Object> claimArr = Arrays.asList(claim.as(Object[].class));
            List<Object> valueArr = Arrays.asList((Object[]) value);
            isValid = claimArr.containsAll(valueArr);
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.",
                    claimName));
        }
    }

    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture) {
        Date today = clock.getToday();
        today.setTime((long) Math.floor((today.getTime() / 1000) * 1000)); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }

    private void assertValidAudienceClaim(List<String> audience, Set<String> value) {
        if (audience == null || audience.stream().noneMatch(value::contains)) {
            throw new InvalidClaimException(
                    "The Claim 'aud' value doesn't contain at least one of the required audiences.");
        }
    }

    final static class ClockImpl implements Clock {

        ClockImpl() {
        }

        @Override
        public Date getToday() {
            return new Date();
        }
    }

    /**
     * The Verification class holds the Claims required by a JWT to be valid.
     */
    public static class BaseVerification {
        private final Algorithm algorithm;

        private final Map<String, Object> claims;

        private long defaultLeeway;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultLeeway = 0;
        }

        /**
         * Require a specific Audience ("aud") claim.
         *
         * @param audience
         *            the required Audience value
         * @return this same Verification instance.
         */
        public BaseVerification withAudience(String... audience) {
            val audiences = new HashSet<String>(Arrays.asList(audience));
            requireClaim(PublicClaims.AUDIENCE, audiences);
            return this;
        }

        /**
         * Define the default window in seconds in which the Not Before, Issued At and
         * Expires At Claims will still be valid. Setting a specific leeway value on a
         * given Claim will override this value for that Claim.
         *
         * @param leeway
         *            the window in seconds in which the Not Before, Issued At and
         *            Expires At Claims will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException
         *             if leeway is negative.
         */
        public BaseVerification acceptLeeway(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            this.defaultLeeway = leeway;
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name
         *            the Claim's name.
         * @param value
         *            the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException
         *             if the name is null.
         */
        public BaseVerification withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration
         * already provided.
         *
         * @return a new JWTVerifier instance.
         */
        public JWTVerifier build() {
            return this.build(new ClockImpl());
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration
         * already provided. ONLY FOR TEST PURPOSES.
         *
         * @param clock
         *            the instance that will handle the current time.
         * @return a new JWTVerifier instance with a custom Clock.
         */
        public JWTVerifier build(Clock clock) {
            addLeewayToDateClaims();
            return new JWTVerifier(algorithm, claims, clock);
        }

        private void assertPositive(long leeway) {
            if (leeway < 0) {
                throw new IllegalArgumentException("Leeway value can't be negative.");
            }
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addLeewayToDateClaims() {
            if (!claims.containsKey(PublicClaims.EXPIRES_AT)) {
                claims.put(PublicClaims.EXPIRES_AT, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.NOT_BEFORE)) {
                claims.put(PublicClaims.NOT_BEFORE, defaultLeeway);
            }
        }

        private void requireClaim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
                return;
            }
            claims.put(name, value);
        }
    }
}
