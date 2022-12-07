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

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonUtils;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.Objects;

/**
 * A convenient class useful to define a JOSE Header containing the parameters describing the cryptographic operations and parameters employed. At present only a subset
 * of the header parameter specified within RFC 7515 is supported. To create an actual {@code JOSEHeader} instance use one of the static factory methods. Two of them provide
 * special builders to programmatically create a {@code JOSEHeader} instance. The third expects a suitable {@code JsonObject}.
 *
 * <p style="font-weight: bold">Example</p>
 * First we generate a key pair and build a JSON Web Key:
 * <pre>KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
 *ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
 *keyPairGenerator.initialize(ecGenParameterSpec);
 *KeyPair keyPair = keyPairGenerator.generateKeyPair();
 *JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
 *    .withKid(UUID.randomUUID().toString())
 *    .build();</pre>
 *
 * Now we can programmatically build a {@code JOSEHeader}:
 *<pre>JOSEHeader joseHeader = JOSEHeader.of(jsonWebPublicKey)
 *    .withTyp("JWT")
 *    .build();</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4">Section 4 of RFC 7515</a>
 * @author Christof Reichardt
 */
public class JOSEHeader implements Traceable {

    final String alg;
    final String typ;
    final String kid;
    final JsonWebPublicKey jsonWebPublicKey;

    /**
     * Returns the configured "alg" (Algorithm).
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1">Section 4.1.1 of RFC 7515</a>
     * @return the configured "alg".
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Returns the configured "typ" (Type).
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9">Section 4.1.9 of RFC 7515</a>
     * @return the configured "typ".
     */
    public String getTyp() {
        return typ;
    }

    /**
     * Returns the configured "kid" (Key ID)
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4">Section 4.1.4 of RFC 7515</a>
     * @return the configured "kid".
     */
    public String getKid() {
        return kid;
    }

    /**
     * Returns the configured "jwk" (JSON Web Key)
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3">Section 4.1.3 of RFC 7515</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517, JSON Web Key (JWK)</a>
     * @return the configured "jwk".
     */
    public JsonWebPublicKey getJsonWebPublicKey() {
        return jsonWebPublicKey;
    }

    JOSEHeader(AlgorithmBuilder algorithmBuilder) {
        if (!JWSBase.ALGO_MAP.containsKey(algorithmBuilder.alg)) {
            throw new IllegalArgumentException(String.format("Unsupported algorithm '%s'.", algorithmBuilder.alg));
        }
        this.alg = algorithmBuilder.alg;
        this.typ = algorithmBuilder.typ;
        this.kid = algorithmBuilder.kid;
        this.jsonWebPublicKey = null;
    }

    JOSEHeader(PublicKeyBuilder publicKeyBuilder) {
        this.alg = publicKeyBuilder.alg;
        this.kid = publicKeyBuilder.kid;
        this.typ = publicKeyBuilder.typ;
        this.jsonWebPublicKey = publicKeyBuilder.jsonWebPublicKey;
    }

    /**
     * Checks if this JOSE header is equal to another header.
     * Compares this {@code JOSEHeader} with another ensuring that it contains the same configuration. Only objects of type {@code JOSEHeader} are considered, other
     * types return false.
     *
     * @param object the object to check, null returns false
     * @return true if this is equal to the other header
     */
    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        JOSEHeader that = (JOSEHeader) object;
        return alg.equals(that.alg) && Objects.equals(typ, that.typ) && Objects.equals(kid, that.kid) && Objects.equals(jsonWebPublicKey, that.jsonWebPublicKey);
    }

    /**
     * A hash code for this header.
     *
     * @return a suitable hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(alg, typ, kid, jsonWebPublicKey);
    }

    /**
     * Creates a special builder for a {@code JOSEHeader}. Use this variant to build a {@code JOSEHeader} if you don't want to specify a JSON web key within the header.
     *
     * @param alg the desired "alg" parameter.
     * @return an {@code AlgorithmBuilder}.
     */
    public static AlgorithmBuilder of(String alg) {
        return new AlgorithmBuilder(alg);
    }

    /**
     * Creates a special builder for a {@code JOSEHeader}. Use this variant to build a {@code JOSEHeader} if you want to specify a JSON web key within the header. The corresponding
     * "alg" parameter will be deduced from the given public key.
     *
     * @param jsonWebPublicKey the desired public key referenced by the "jwk" parameter.
     * @return a {@code PublicKeyBuilder}.
     */
    public static PublicKeyBuilder of(JsonWebPublicKey jsonWebPublicKey) {
        return new PublicKeyBuilder(jsonWebPublicKey);
    }

    /**
     * A builder for a {@code JOSEHeader} preconfigured with the "alg" parameter.
     */
    public static class AlgorithmBuilder {
        final String alg;
        String typ = null;
        String kid = null;

        public AlgorithmBuilder(String alg) {
            this.alg = alg;
        }

        public AlgorithmBuilder withTyp(String typ) {
            this.typ = typ;
            return this;
        }

        public AlgorithmBuilder withKid(String kid) {
            this.kid = kid;
            return this;
        }

        public JOSEHeader build() {
            return new JOSEHeader(this);
        }
    }

    /**
     * A builder for a {@code JOSEHeader} preconfigured with a JSON web (public) key.
     */
    public static class PublicKeyBuilder implements Traceable {
        static Map<String, String> ecAlgoMap = Map.of("secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)", "ES256");

        final String alg;
        final JsonWebPublicKey jsonWebPublicKey;
        final String kid;
        String typ = null;

        public PublicKeyBuilder(JsonWebPublicKey jsonWebPublicKey) {
            this.jsonWebPublicKey = jsonWebPublicKey;
            this.alg = algorithm();
            this.kid = this.jsonWebPublicKey.getKid();
        }

        String algorithm() {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("String", this, "algorithm()");

            try {
                tracer.out().printfIndentln("this.jsonWebPublicKey = %s", this.jsonWebPublicKey);
                String keyType = this.jsonWebPublicKey.getKeyType();
                if (Objects.equals("EC", keyType)) {
                    if (!(this.jsonWebPublicKey.getAlgorithmParameterSpec() instanceof ECParameterSpec ecParameterSpec)) {
                        throw new IllegalArgumentException("No ECParameterSpec found.");
                    }
                    if (!ecAlgoMap.containsKey(ecParameterSpec.toString())) {
                        throw new IllegalArgumentException(String.format("Unsupported curve '%s' found.", ecParameterSpec));
                    }
                    return ecAlgoMap.get(ecParameterSpec.toString());
                } else if (Objects.equals("RSA", keyType)) {
                    if (!(this.jsonWebPublicKey.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
                        throw new IllegalArgumentException("Inappropriate key.");
                    }
                    int keysize = rsaPublicKey.getModulus().bitLength() / 8;
                    tracer.out().printfIndentln("keysize = %d bytes", keysize);

                    return "RS256"; // TODO: think about different algorithms that is RSA with a different hash algorithm than SHA-256
                } else {
                    throw new IllegalArgumentException(String.format("Unsupported key type '%s'.", keyType));
                }
            } finally {
                tracer.wayout();
            }
        }

        public PublicKeyBuilder withTyp(String typ) {
            this.typ = typ;
            return this;
        }

        public JOSEHeader build() {
            return new JOSEHeader(this);
        }

        @Override
        public AbstractTracer getCurrentTracer() {
            return TracerFactory.getInstance().getCurrentPoolTracer();
        }
    }

    /**
     * Converts this {@code JOSEHeader} into a plain {@code JsonObject}.
     *
     * @return a {@code JsonObject} corresponding to this {@code JOSEHeader}.
     * @see <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonobject">JsonObject (Jakarta EE Platform API)</a>
     */
    public JsonObject toJson() {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder()
                .add("alg", this.alg);
        if (this.typ != null) {
            jsonObjectBuilder.add("typ", this.typ);
        }
        if (this.kid != null) {
            jsonObjectBuilder.add("kid", this.kid);
        }
        if (this.jsonWebPublicKey != null) {
            jsonObjectBuilder.add("jwk", this.jsonWebPublicKey.toJson());
        }

        return jsonObjectBuilder.build();
    }

    /**
     * Factory method to create a {@code JOSEHeader} instance from a plain {@code JsonObject}.
     *
     * @param joseHeaderView the given {@code JsonObject}.
     * @return a {@code JOSEHeader}
     * @throws GeneralSecurityException forwarded from the Java Platform API, indicates difficulties when creating a JSON web key from the given {@code JsonObject}.
     * @see <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonobject">JsonObject (Jakarta EE Platform API)</a>
     */
    static public JOSEHeader fromJson(JsonObject joseHeaderView) throws GeneralSecurityException {
        AbstractTracer tracer = TracerFactory.getInstance().getCurrentPoolTracer();
        tracer.entry("void", JOSEHeader.class, "fromJson(JsonObject joseHeaderView)");

        try {
            String alg = JsonUtils.orElseThrow(joseHeaderView, "alg", JsonString.class).getString();
            String typ = joseHeaderView.getString("typ", null);
            String kid = joseHeaderView.getString("kid", null);
            JsonWebPublicKey jsonWebPublicKey = null;
            if (joseHeaderView.containsKey("jwk")) {
                if (joseHeaderView.get("jwk").getValueType() != JsonValue.ValueType.OBJECT) {
                    throw new IllegalArgumentException("'jwk' should be an object.");
                }
                jsonWebPublicKey = JsonWebPublicKey.fromJson(joseHeaderView.getJsonObject("jwk"));
            }

            if (Objects.nonNull(jsonWebPublicKey)) {
                if (!Objects.equals(kid, jsonWebPublicKey.getKid())) {
                    throw new IllegalArgumentException("Ambigous kids.");
                }
                if (Objects.equals("ES256", alg)) {
                    if (!Objects.equals("EC", jsonWebPublicKey.getKeyType())) {
                        throw new IllegalArgumentException(String.format("Inappropriate key type '%s' for algorithm '%s'.", jsonWebPublicKey.getKeyType(), alg));
                    }
                    if (jsonWebPublicKey.getAlgorithmParameterSpec() instanceof ECParameterSpec ecParameterSpec) {
                        if (!ecParameterSpec.toString().startsWith("secp256r1")) {
                            throw new IllegalArgumentException(String.format("Inappropriate curve '%s' for algorithm '%s'.", ecParameterSpec, alg));
                        }
                    } else {
                        throw new IllegalArgumentException("Inappropriate algorithm parameters.");
                    }
                } else if (Objects.equals("RS256", alg)) {
                    if (!Objects.equals("RSA", jsonWebPublicKey.getKeyType())) {
                        throw new IllegalArgumentException(String.format("Inappropriate key type '%s' for algorithm '%s'.", jsonWebPublicKey.getKeyType(), alg));
                    }
                } else if (Objects.equals("HS256", alg)) {
                    throw new IllegalArgumentException("Symmetric algorithms don't use public keys.");
                }
            }

            JOSEHeader joseHeader;
            if (jsonWebPublicKey != null) {
                joseHeader = JOSEHeader.of(jsonWebPublicKey)
                        .withTyp(typ)
                        .build();
            } else {
                joseHeader = JOSEHeader.of(alg)
                        .withKid(kid)
                        .withTyp(typ)
                        .build();
            }

            return joseHeader;
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
