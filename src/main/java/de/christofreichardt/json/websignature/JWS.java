/*
 * Copyright (C) 2022, 2025, Christof Reichardt
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

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import de.christofreichardt.json.websignature.interfaces.BeforeHeader;
import de.christofreichardt.json.websignature.interfaces.BeforeKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKid;
import de.christofreichardt.json.websignature.interfaces.BeforePayload;
import de.christofreichardt.json.websignature.interfaces.SignatureBegin;
import de.christofreichardt.json.websignature.interfaces.SignatureEnd;
import de.christofreichardt.json.websignature.interfaces.ValidationBegin;
import de.christofreichardt.json.websignature.interfaces.ValidationEnd;
import jakarta.json.JsonStructure;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.SecretKey;

/**
 * This class provides a Fluent API for generating and validating JSON Web Signatures.
 * <p style="font-weight: bold">Example 1: Signing</p>
 * Firstly, we create a keypair:
 * <pre>JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
 *         .build();</pre>
 *  Secondly, we need a payload:
 *  <pre>String strSepaTransfer = """
 *         {
 *           "sepa-transfer": {
 *             "originator": {
 *               "iban": "DE02300606010002474689",
 *               "name": "Max Mustermann"
 *             },
 *             "date-time": "2025-05-28T13:32:07.1821996+02:00[Europe/Berlin]",
 *             "transfer-amount": 123.45,
 *             "purpose": "Rechnung-1234",
 *             "recipient": {
 *               "iban": "AT022040400040102634",
 *               "name": "Muster-Hotel"
 *             }
 *           }
 *         }
 *         """;
 *JsonObject sepaTransfer;
 *try (StringReader stringReader = new StringReader(strSepaTransfer);
 *      JsonReader jsonReader = Json.createReader(stringReader)) {
 *     sepaTransfer = jsonReader.readObject();
 *}</pre>
 * Please note that all bank accounts are fictitious.
 * Now we can sign the {@code sepaTransfer} using the Fluent API:
 * <pre>String kid = UUID.randomUUID().toString();
 *JWSCompactSerialization compactSerialization = JWS.createSignature()
 *         .webkey(jsonWebKeyPair)
 *         .typ("JOSE")
 *         .kid(kid)
 *         .payload(sepaTransfer)
 *         .sign(new PrettyStringConverter());</pre>
 * This will create the following JOSE header within the first part of the JWS Compact Serialization:
 * <pre>{
 *     "alg": "ES256",
 *     "typ": "JOSE",
 *     "kid": "2973fb0a-3a6b-48b9-ad5f-c1c9ef1bc79e",
 *     "jwk": {
 *         "kty": "EC",
 *         "crv": "P-256",
 *         "x": "RV9KxZnDewjiQjoalsYUpjT3n1bbt-62b6HcDOt0lCE",
 *         "y": "Y7wtjOBdD9nPW-DMdUw0qL-PCBn4031vA-TMvGMVBe8"
 *     }
 * }</pre>
 * (You will get other x,y coordinates with virtual certainty).
 * <p style="font-weight: bold">Example 2: Validating</p>
 * Firstly, we need a {@code JsonWebPublicKey}. For this example we simply create one from the given "jwk" header parameter:
 * <pre>JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(compactSerialization.joseHeader().getJsonObject("jwk"));</pre>
 * In the real world, however, you would need to verify at least if the "kid" parameter checks, that is it refers to the authentic key (pair).
 * Now we can validate the signature:
 * <pre>boolean validated = JWS.createValidator()
 *         .compactSerialization(compactSerialization)
 *         .webkey(jsonWebPublicKey)
 *         .validate();
 *assert validated;</pre>
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
    protected static class Signature implements SignatureBegin, BeforePayload, BeforeHeader, BeforeKid, SignatureEnd, Traceable {

        JsonWebKey jsonWebKey;
        JsonStructure payload;
        String kid;
        String typ;
        String strPayload;
        String strHeader;

        @Override
        public SignatureEnd payload(JsonStructure payload) {
            this.payload = payload;
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
            return sign(JsonStructure::toString);
        }

        @Override
        public JWSCompactSerialization sign(final Json2StringConverter converter) throws GeneralSecurityException {
            assert Objects.nonNull(this.payload) || Objects.nonNull(this.strPayload) : "No payload is given.";

            Key key = signingKey();
            Optional<JOSEHeader> optionalJOSEHeader = buildJoseHeader();

            JWSSigner jwsSigner;
            if (Objects.nonNull(this.payload)) {
                jwsSigner = optionalJOSEHeader
                        .map(joseHeader -> new JWSSigner(joseHeader.toJson(), this.payload, converter))
                        .orElseGet(() -> new JWSSigner(this.strHeader, converter.convert(this.payload)));
            } else if (Objects.nonNull(this.strPayload)) {
                jwsSigner = optionalJOSEHeader
                        .map(joseHeader -> new JWSSigner(converter.convert(joseHeader.toJson()), this.strPayload))
                        .orElseGet(() -> new JWSSigner(this.strHeader, this.strPayload));
            } else {
                throw new IllegalStateException();
            }

            return jwsSigner.sign(key);
        }

        @Override
        public BeforePayload kid(String kid) {
            if (Objects.nonNull(this.jsonWebKey.getKid()) && !Objects.equals(this.jsonWebKey.getKid(), kid)) {
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

        private Optional<JOSEHeader> buildJoseHeader() throws GeneralSecurityException {
            JOSEHeader joseHeader = null;
            if (Objects.isNull(this.strHeader)) {
                if (this.jsonWebKey instanceof JsonWebSecretKey jsonWebSecretKey) {
                    JOSEHeader.AlgorithmBuilder algorithmBuilder = JOSEHeader.of(jsonWebSecretKey.getAlgorithm())
                            .withTyp(this.typ);
                    if (Objects.nonNull(this.kid)) {
                        algorithmBuilder.withKid(this.kid);
                    }
                    joseHeader = algorithmBuilder.build();
                } else if (this.jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair) {
                    JOSEHeader.PublicKeyBuilder publicKeyBuilder = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                            .withTyp(this.typ);
                    if (Objects.nonNull(this.kid)) {
                        publicKeyBuilder.withKid(this.kid);
                    }
                    joseHeader = publicKeyBuilder.build();
                } else {
                    throw new UnsupportedOperationException();
                }
            }

            return Optional.ofNullable(joseHeader);
        }

        private Key signingKey() {
            Key key;
            if (this.jsonWebKey instanceof JsonWebSecretKey jsonWebSecretKey) {
                key = jsonWebSecretKey.getSecretKey();
            } else if (this.jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair) {
                key = jsonWebKeyPair.getKeyPair().getPrivate();
            } else {
                throw new UnsupportedOperationException();
            }

            return key;
        }

        @Override
        public AbstractTracer getCurrentTracer() {
            return TracerFactory.getInstance().getDefaultTracer();
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
        public ValidationEnd webkey(JsonWebPublicKey jsonWebPublicKey) {
            this.key = jsonWebPublicKey.getPublicKey();
            return this;
        }

        @Override
        public ValidationEnd webkey(JsonWebSecretKey jsonWebSecretKey) {
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
