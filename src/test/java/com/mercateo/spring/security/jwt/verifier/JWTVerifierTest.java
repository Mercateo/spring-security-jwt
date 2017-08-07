package com.mercateo.spring.security.jwt.verifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

import javaslang.control.Try;
import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTVerifierTest {

    private static final String NAMESPACE_PREFIX = "https://test.org/";

    @Mock
    private JWTKeyset jwks;

    private String keyId = "4711";

    private Algorithm algorithm;

    private JWTVerifier uut;

    private Date expiresAt;

    private Date issuedAt;

    @Before
    public void setUp() throws Exception {
        final RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKey(getClass().getResourceAsStream(
                "rsa-private.pem"), "RSA");
        final RSAPublicKey publicKey = (RSAPublicKey) PemUtils.readPublicKey(getClass().getResourceAsStream(
                "rsa-public.pem"), "RSA");
        algorithm = Algorithm.RSA256(publicKey, privateKey);

        final HashMap<String, Object> additionalValues = new HashMap<>();
        additionalValues.put("n", Base64.encodeBase64String(publicKey.getModulus().toByteArray()));
        additionalValues.put("e", Base64.encodeBase64String(publicKey.getPublicExponent().toByteArray()));
        Jwk jwk = new Jwk(keyId, "RSA", "RSA256", null, null, null, Collections.emptyList(), null, additionalValues);
        when(jwks.getKeysetForId(keyId)).thenReturn(Try.success(jwk));
        assertThat(jwks.getKeysetForId(keyId)).isNotNull();

        uut = new JWTVerifierFactory(jwks).create();
    }

    @Test
    public void shouldVerifyJWT() {
        val originalToken = addVerifiedJWTAuthHeader();

        val jwt = uut.verify(originalToken);

        assertThat(jwt.getClaim(NAMESPACE_PREFIX + "user_id").asString()).isEqualTo("<userId>");
        assertThat(jwt.getClaim("scope").asString()).isEqualTo("<scope>");
        assertThat(jwt.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(jwt.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(jwt.getIssuer()).isEqualTo("https://test.org/");

        assertThat(jwt.getClaim("undefined").asString()).isNull();
    }

    private String addVerifiedJWTAuthHeader() {
        val now = System.currentTimeMillis() / 1000 * 1000;
        issuedAt = new Date(now);
        expiresAt = new Date(now + 30000);
        return JWT
            .create()
            .withKeyId(keyId)
            .withClaim(NAMESPACE_PREFIX + "user_id", "<userId>")
            .withClaim(NAMESPACE_PREFIX + "undefined", "<undefined>")
            .withClaim("scope", "<scope>")
            .withIssuedAt(issuedAt)
            .withExpiresAt(expiresAt)
            .withIssuer("https://test.org/")
            .withSubject("<subject>")
            .sign(algorithm);
    }

}
