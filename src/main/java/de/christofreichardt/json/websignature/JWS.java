/*
 * Copyright (C) 2022, Christof Reichardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.christofreichardt.json.websignature;

import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKid;
import de.christofreichardt.json.websignature.interfaces.BeforePayload;
import de.christofreichardt.json.websignature.interfaces.BeforeHeader;
import de.christofreichardt.json.websignature.interfaces.SignatureBegin;
import de.christofreichardt.json.websignature.interfaces.SignatureEnd;
import de.christofreichardt.json.websignature.interfaces.ValidationBegin;
import de.christofreichardt.json.websignature.interfaces.ValidationEnd;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;
import javax.crypto.SecretKey;
import jakarta.json.JsonObject;

/**
 * This class provides a Fluent API for generating and validating JSON Web Signatures.
 *
 * <p style="font-weight: bold">Example 1: Signing</p>
 * Firstly, we create a keypair:
 * <pre>KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
 *ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
 *keyPairGenerator.initialize(ecGenParameterSpec);
 *KeyPair keyPair = keyPairGenerator.generateKeyPair();</pre>
 *  Secondly, we read a JsonObject from a file:
 *  <pre>Path path = Path.of("json", "my-json-object.json");
 *JsonObject jsonObject;
 *try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
 *    jsonObject = jsonReader.readObject();
 *}</pre>
 * Now we can sign the {@code jsonObject} using the Fluent API:
 * <pre>JWSCompactSerialization compactSerialization = JWS.createSignature()
 *     .key(keyPair)
 *     .typ("JOSE")
 *     .payload(jsonObject)
 *     .sign();</pre>
 * This will create the following JOSE header within the first part of the JWS Compact Serialization:
 * <pre>{
 *   "alg": "ES256",
 *   "typ": "JOSE",
 *   "jwk": {
 *       "kty": "EC",
 *       "crv": "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)",
 *       "x": "_ickpOtyfliWJQv3QUmYR4PboGupj-VuoVYAa1ACvDk",
 *       "y": "VSoYSDk3E-E857UolPZmC2htBPUJ69HIaZY3hR7G_PA"
 *   }
 *}</pre>
 * (You will get other x,y coordinates with virtual certainty).
 * <p style="font-weight: bold">Example 2: Validating</p>
 * Firstly, we create a {@code JsonWebPublicKey} from the given {@code jwk} header parameter:
 * <pre>JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(compactSerialization.joseHeader().getJsonObject("jwk"));</pre>
 * Now we can validate the signature:
 * <pre>boolean validated = JWS.createValidator()
 *    .compactSerialization(compactSerialization)
 *    .key(jsonWebPublicKey)
 *    .validate();
 *assertThat(validated).isTrue();</pre>
 * @author Christof Reichardt
 * @see de.christofreichardt.json.webkey.JsonWebPublicKey
 * @see de.christofreichardt.json.websignature.JWSCompactSerialization
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1">Section 3.1 of RFC 7515</a>
 */
public class JWS {
    private JWS() {
    }

    /**
     * Entry point for creating signatures.
     *
     * @return a SignatureBegin instance, an interface of the Fluent API.
     */
    public static SignatureBegin createSignature() {
        return new Signature();
    }

    /**
     * Entry point for validating signatures.
     *
     * @return  a ValidationBegin instance, an interface of the Fluent API.
     */
    public static ValidationBegin createValidator() {
        return new Validator();
    }

    /**
     * Implements all interfaces of the Fluent API related to creating signatures.
     */
    protected static class Signature implements SignatureBegin, BeforePayload, BeforeHeader, BeforeKid, SignatureEnd {

        JsonWebKey jsonWebKey;
        JsonObject payload;
        String kid;
        String typ;
        Json2StringConverter converter;
        String strPayload;
        String strHeader;

        @Override
        public SignatureEnd payload(JsonObject payload) {
            this.payload = payload;
            return this;
        }

        @Override
        public SignatureEnd payload(JsonObject payload, Json2StringConverter converter) {
            this.payload = payload;
            this.converter = converter;
            return this;
        }

        @Override
        public SignatureEnd payload(String strPayload) {
            this.strPayload = strPayload;
            return this;
        }

        @Override
        public BeforeHeader webkey(JsonWebKeyPair jsonWebKeyPair) {
            this.jsonWebKey = jsonWebKeyPair;
            return this;
        }

        @Override
        public BeforeHeader webkey(JsonWebSecretKey jsonWebSecretKey) {
            this.jsonWebKey = jsonWebSecretKey;
            return this;
        }

        @Override
        public BeforeHeader key(KeyPair keyPair) {
            this.jsonWebKey = JsonWebKeyPair.of(keyPair)
                    .build();
            return this;
        }

        @Override
        public BeforeHeader key(SecretKey secretKey) {
            this.jsonWebKey = JsonWebSecretKey.of(secretKey)
                    .build();
            return this;
        }

        @Override
        public JWSCompactSerialization sign() throws GeneralSecurityException {
            JWSCompactSerialization compactSerialization;
            JOSEHeader joseHeader;
            JWSSigner jwsSigner;
            Key key;

            if (this.jsonWebKey instanceof JsonWebSecretKey jsonWebSecretKey) {
                joseHeader = JOSEHeader.of(jsonWebSecretKey.getAlgorithm())
                        .withKid(this.kid)
                        .withTyp(this.typ)
                        .build();
                key = jsonWebSecretKey.getSecretKey();
            } else if (this.jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair) {
                joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .withTyp(this.typ)
                        .build();
                key = jsonWebKeyPair.getKeyPair().getPrivate();
            } else {
                throw new UnsupportedOperationException();
            }

            if (Objects.nonNull(this.payload)) {
                if (Objects.isNull(this.strHeader)) {
                    if (Objects.nonNull(this.converter)) {
                        jwsSigner = new JWSSigner(joseHeader.toJson(), this.payload, this.converter);
                    } else {
                        jwsSigner = new JWSSigner(joseHeader.toJson(), this.payload);
                    }
                } else if (Objects.nonNull(this.strHeader)) {
                    if (Objects.nonNull(this.converter)) {
                        jwsSigner = new JWSSigner(this.strHeader, this.converter.convert(this.payload));
                    } else {
                        jwsSigner = new JWSSigner(this.strHeader, this.payload.toString());
                    }
                } else {
                    throw new IllegalStateException();
                }
            } else if (Objects.nonNull(this.strPayload)) { // TODO: make some sanity checks within this branch
                if (Objects.isNull(this.strHeader)) {
                    if (Objects.nonNull(this.converter)) {
                        jwsSigner = new JWSSigner(this.converter.convert(joseHeader.toJson()), this.strPayload);
                    } else {
                        jwsSigner = new JWSSigner(joseHeader.toJson().toString(), this.strPayload);
                    }
                } else {
                    if (Objects.nonNull(this.converter)) {
                        jwsSigner = new JWSSigner(this.strHeader, this.strPayload); // TODO: converter is superfluous, think about it.
                    } else {
                        jwsSigner = new JWSSigner(this.strHeader, this.strPayload);
                    }
                }
            } else {
                throw new IllegalStateException();
            }

            compactSerialization = jwsSigner.sign(key);

            return compactSerialization;
        }

        @Override
        public BeforePayload kid(String kid) {
            if (!Objects.equals(this.jsonWebKey.getKid(), kid)) {
                throw new IllegalArgumentException("Ambigous kids.");
            }
            this.kid = kid;
            return this;
        }

        @Override
        public BeforeKid typ(String typ) {
            this.typ = typ;
            return this;
        }

        @Override
        public BeforePayload header(String strHeader) {
            this.strHeader = strHeader;
            return this;
        }
    }

    /**
     * Implements all interfaces of the Fluent API related to validating signatures.
     */
    protected static class Validator implements ValidationBegin, BeforeKey, ValidationEnd {

        JWSCompactSerialization compactSerialization;
        Key key;

        @Override
        public ValidationEnd key(PublicKey publicKey) {
            this.key = publicKey;
            return this;
        }

        @Override
        public ValidationEnd key(SecretKey secretKey) {
            this.key = secretKey;
            return this;
        }

        @Override
        public ValidationEnd key(JsonWebPublicKey jsonWebPublicKey) {
            this.key = jsonWebPublicKey.getPublicKey();
            return this;
        }

        @Override
        public ValidationEnd key(JsonWebSecretKey jsonWebSecretKey) {
            this.key = jsonWebSecretKey.getSecretKey();
            return this;
        }

        @Override
        public BeforeKey compactSerialization(JWSCompactSerialization compactSerialization) {
            this.compactSerialization = compactSerialization;
            return this;
        }

        @Override
        public boolean validate() throws GeneralSecurityException {
            JWSValidator jwsValidator = new JWSValidator(this.compactSerialization);
            return jwsValidator.validate(this.key);
        }
    }
}
