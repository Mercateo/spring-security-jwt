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
package com.mercateo.spring.security.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

class PemUtils {

    private static byte[] parsePEM(InputStream inputStream) throws IOException {
        try (PemReader reader = new PemReader(new InputStreamReader(inputStream))) {
            PemObject pemObject = reader.readPemObject();
            return pemObject.getContent();
        }
    }

    private static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }
        return null;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        }
        return null;
    }

    static PublicKey readPublicKey(InputStream inputStream, String algorithm) throws IOException {
        byte[] bytes = PemUtils.parsePEM(inputStream);
        return PemUtils.getPublicKey(bytes, algorithm);
    }

    static PrivateKey readPrivateKey(InputStream inputStream, String algorithm) throws IOException {
        byte[] bytes = PemUtils.parsePEM(inputStream);
        return PemUtils.getPrivateKey(bytes, algorithm);
    }

}
