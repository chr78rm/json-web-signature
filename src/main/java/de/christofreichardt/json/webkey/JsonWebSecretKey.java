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

package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.JsonUtils;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;

/**
 * Convenient for the handling of secret keys in the spirit of RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
 *
 * @author Christof Reichardt
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517 (JSON Web Key)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html">RFC 7518 (JSON Web Algorithms)</a>
 */
final public class JsonWebSecretKey extends JsonWebKey {

    final static Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256", "HmacSHA512", "HS512");
    final static Map<String, String> JSON2JDK_ALGO_MAP = new HashMap<>();

    static {
        JDK2JSON_ALGO_MAP.forEach((key, value) -> JSON2JDK_ALGO_MAP.put(value, key));
    }

    /**
     * Creates the default builder for a {@code JsonWebSecretKey}. Use this variant if you don't already have a secret key.
     *
     * @return a {@link de.christofreichardt.json.webkey.JsonWebSecretKey.Builder}.
     */
    public static Builder of() {
        return new Builder();
    }

    /**
     * Creates a special builder for a {@code JsonWebSecretKey}. Use this variant if you already have a {@code SecretKey}.
     *
     * @param secretKey the given {@code SecretKey}
     * @return a {@link de.christofreichardt.json.webkey.JsonWebSecretKey.SecretKeyBuilder}.
     * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/SecretKey.html">SecretKey</a>
     * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/KeyGenerator.html">KeyGenerator</a>
     */
    public static SecretKeyBuilder of(SecretKey secretKey) {
        return new SecretKeyBuilder(secretKey);
    }

    final SecretKey secretKey;
    final String algorithm;

    /**
     * Returns the wrapped {@code SecretKey}.
     *
     * @return the wrapped {@code SecretKey} instance.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * Return the algorithm to be used with the wrapped {@code SecretKey}, e.g. {@code HS256}.
     *
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    JsonWebSecretKey(Builder builder) {
        super(builder.kid, "oct");
        this.secretKey = builder.secretKey;
        this.algorithm = JDK2JSON_ALGO_MAP.get(this.secretKey.getAlgorithm());
    }

    JsonWebSecretKey(SecretKeyBuilder secretKeyBuilder) {
        super(secretKeyBuilder.kid, "oct");
        this.secretKey = secretKeyBuilder.secretKey;
        this.algorithm = JDK2JSON_ALGO_MAP.get(this.secretKey.getAlgorithm());
    }

    /**
     * Returns a textual representation of this {@code JsonWebSecretKey}.
     *
     * @return a textual representation of this {@code JsonWebSecretKey}.
     */
    @Override
    public String toString() {
        return String.format("%s[kid=%s, keyType=%s, algorithm=%s, keysize=%d]", this.getClass().getSimpleName(),
                this.kid, this.keyType, this.secretKey.getAlgorithm(), Objects.nonNull(this.secretKey.getEncoded()) ? this.secretKey.getEncoded().length * 8 : -1);
    }

    /**
     * Compares this {@code JsonWebSecretKey} with another {@code JsonWebSecretKey}.
     * Compares this {@code JsonWebSecretKey} with another ensuring that it contains the same configuration. Only objects of type {@code JsonWebSecretKey} are considered, other
     * types return false.
     *
     * @param object the object to check, null returns false
     * @return true if this is equal to the other {@code JsonWebSecretKey}
     */
    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        JsonWebSecretKey that = (JsonWebSecretKey) object;

        return Objects.equals(this.secretKey.getAlgorithm(), that.secretKey.getAlgorithm())
                && MessageDigest.isEqual(this.secretKey.getEncoded(), that.secretKey.getEncoded())
                && Objects.equals(this.kid, that.kid)
                && Objects.equals(this.keyType, that.keyType);
    }

    /**
     * A hash code for this {@code JsonWebSecretKey}.
     *
     * @return a suitable hash code.
     */
    @Override
    public int hashCode() {
        int hashCode = 0;
        for (int i = 0; i < this.secretKey.getEncoded().length; i++) {
            hashCode += this.secretKey.getEncoded()[i] * i;
        }

        return Objects.hash(this.algorithm, this.kid, this.keyType) ^ hashCode;
    }

    /**
     * Converts this {@code JsonWebSecretKey} into a plain {@code JsonObject}.
     *
     * @return a {@code JsonObject} corresponding to this {@code JsonWebSecretKey}.
     * @see <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonobject">JsonObject (Jakarta EE Platform API)</a>
     */
    @Override
    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(super.toJson());
            tracer.out().printfIndentln("octets(secretKey) = %s", JsonWebKeyUtils.formatBytes(this.secretKey.getEncoded()));
            jsonObjectBuilder.add("k", BASE64_URL_ENCODER.encodeToString(this.secretKey.getEncoded()));
            jsonObjectBuilder.add("alg", this.algorithm);

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    /**
     * A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebSecretKey}s by specifying an algorithm and a keysize.
     */
    public static class Builder extends JsonWebKey.Builder<Builder> {

        SecretKey secretKey;
        String algorithm = "HmacSHA256";
        int keysize = 256;

        /**
         * Indicates the {@code keysize} to be used when generating the {@code SecretKey}.
         *
         * @param keysize the to be used {@code keysize}
         * @return this {@code JsonWebSecretKey.Builder} instance
         */
        public Builder withKeysize(int keysize) {
            this.keysize = keysize;
            return this;
        }

        /**
         * Indicates the {@code algorithm} to be used when generating the {@code SecretKey}.
         *
         * @param algorithm the to be used {@code algorithm}
         * @return this {@code JsonWebSecretKey.Builder} instance
         * @throws NoSuchAlgorithmException if the requested algorithm is not supported
         */
        public Builder withAlgorithm(String algorithm) throws NoSuchAlgorithmException {
            if (!JDK2JSON_ALGO_MAP.containsKey(algorithm)) {
                throw new NoSuchAlgorithmException();
            }
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Builds the {@code JsonWebSecretKey} with the configured parameters.
         *
         * @return the appropriately configured {@code JsonWebSecretKey} instance
         * @throws NoSuchAlgorithmException relayed from the underlying "Java Cryptography Architecture"
         */
        @Override
        public JsonWebSecretKey build() throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(this.algorithm);
            keyGenerator.init(this.keysize);
            this.secretKey = keyGenerator.generateKey();
            return new JsonWebSecretKey(this);
        }
    }

    /**
     *  A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebSecretKey}s by providing a {@code SecretKey}.
     */
    public static class SecretKeyBuilder extends JsonWebKey.Builder<SecretKeyBuilder> {
        final SecretKey secretKey;

        /**
         * Creates the {@code JsonWebSecretKey.SecretKeyBuilder} preconfigured with the given {@code SecretKey}.
         *
         * @param secretKey the to be used {@code algorithm}
         * @throws IllegalArgumentException if the requested algorithm is not supported
         */
        public SecretKeyBuilder(SecretKey secretKey) throws IllegalArgumentException { // TODO: think about making this a NoSuchAlgorithmException
            if (!JDK2JSON_ALGO_MAP.containsKey(secretKey.getAlgorithm())) {
                throw new IllegalArgumentException();
            }
            this.secretKey = secretKey;
        }

        /**
         * Builds the {@code JsonWebSecretKey} with the configured {@code SecretKey}.
         *
         * @return the appropriately configured {@code JsonWebSecretKey} instance
         */
        @Override
        public JsonWebSecretKey build() {
            return new JsonWebSecretKey(this);
        }
    }

    /**
     * Factory method to create a {@code JsonWebSecretKey} instance from a plain {@code JsonObject}.
     *
     * @param jwkView the given {@code JsonObject}.
     * @return a {@code JsonWebSecretKey}
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    public static JsonWebSecretKey fromJson(JsonObject jwkView) throws GeneralSecurityException {
        String keyType = JsonUtils.orElseThrow(jwkView, "kty", JsonString.class).getString();
        if (!keyType.equals("oct")) {
            throw new UnsupportedOperationException();
        }
        byte[] bytes = BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "k", JsonString.class).getString());
        String algorithm = JsonUtils.orElseThrow(jwkView, "alg", JsonString.class).getString();
        if (!JSON2JDK_ALGO_MAP.containsKey(algorithm)) {
            throw new NoSuchAlgorithmException();
        }
        algorithm = JSON2JDK_ALGO_MAP.get(algorithm);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, algorithm); // TODO: Consider using a SecretKeyFactory
        String kid = jwkView.getString("kid", null);

        return JsonWebSecretKey.of(secretKeySpec)
                .withKid(kid)
                .build();
    }
}
