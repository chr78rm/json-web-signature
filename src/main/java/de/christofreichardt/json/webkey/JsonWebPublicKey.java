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

package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.JsonUtils;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;

/**
 * Convenient for the handling of public keys in the spirit of RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
 *
 * @author Christof Reichardt
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517 (JSON Web Key)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html">RFC 7518 (JSON Web Algorithms)</a>
 */
final public class JsonWebPublicKey extends JsonWebKey {

    /**
     * Creates the builder for a {@code JsonWebPublicKey}.
     *
     * @param publicKey the given public key.
     * @return a {@link de.christofreichardt.json.webkey.JsonWebPublicKey.Builder}.
     */
    public static Builder of(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    final PublicKey publicKey;
    final AlgorithmParameterSpec algorithmParameterSpec;

    /**
     * Returns the contained public key.
     *
     * @return the contained {@code PublicKey}.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Returns the applied {@code AlgorithmParameterSpec}, may be null.
     *
     * @return the applied {@code AlgorithmParameterSpec}.
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    JsonWebPublicKey(Builder builder) {
        super(builder.kid, builder.publicKey.getAlgorithm());
        this.publicKey = builder.publicKey;
        if (this.publicKey instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
    }

    /**
     * Returns a textual representation of this {@code JsonWebPublicKey}.
     *
     * @return a textual representation of this {@code JsonWebPublicKey}.
     */
    @Override
    public String toString() {
        String params = null;
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            params = ecParameterSpec.toString();
        }
        return String.format("%s[kid=%s, keyType=%s, params=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, params); // TODO: there are missing data elements
    }

    /**
     * Compares this {@code JsonWebPublicKey} with another {@code JsonWebPublicKey}.
     * Compares this {@code JsonWebPublicKey} with another ensuring that it contains the same configuration. Only objects of type {@code JsonWebPublicKey} are considered, other
     * types return false.
     *
     * @param object the object to check, null returns false
     * @return true if this is equal to the other {@code JsonWebPublicKey}
     */
    @Override
    public boolean equals(Object object) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("boolean", this, "equals(Object object)");

        try {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;
            JsonWebPublicKey that = (JsonWebPublicKey) object;
            tracer.out().printfIndentln("this.publicKey.getClass().getName() = %s, that.publicKey.getClass().getName() = %s",
                    this.publicKey.getClass().getName(), that.publicKey.getClass().getName());
            boolean isAlgoTheSame;
            if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec1 && that.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec2) {
                tracer.out().printfIndentln("ecParameterSpec1.getClass().getName() = %s", ecParameterSpec1.getClass().getName());
                tracer.out().printfIndentln("ecParameterSpec2.getClass().getName() = %s", ecParameterSpec2.getClass().getName());
                isAlgoTheSame = Objects.equals(ecParameterSpec1.toString(), ecParameterSpec2.toString());
            } else if (this.algorithmParameterSpec instanceof ECParameterSpec) {
                isAlgoTheSame = false;
            } else if (that.algorithmParameterSpec instanceof ECParameterSpec) {
                isAlgoTheSame = false;
            } else if (Objects.isNull(this.algorithmParameterSpec) && Objects.isNull(that.algorithmParameterSpec)) {
                isAlgoTheSame = true;
            } else {
                throw new IllegalArgumentException();
            }
            return Objects.equals(this.publicKey, that.publicKey)
                    && isAlgoTheSame
                    && Objects.equals(this.kid, that.kid)
                    && Objects.equals(this.keyType, that.keyType);
        } finally {
            tracer.wayout();
        }
    }

    /**
     * A hash code for this {@code JsonWebPublicKey}.
     * @return a suitable hash code.
     */
    @Override
    public int hashCode() {
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            return Objects.hash(this.publicKey, ecParameterSpec.toString(), this.kid, this.keyType);
        } else {
            return Objects.hash(this.publicKey, this.algorithmParameterSpec, this.kid, this.keyType);
        }
    }

    /**
     * Converts this {@code JsonWebPublicKey} into a plain {@code JsonObject}.
     *
     * @return a {@code JsonObject} corresponding to this {@code JsonWebPublicKey}.
     * @see <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonobject">JsonObject (Jakarta EE Platform API)</a>
     */
    @Override
    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(super.toJson());
            if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
                String curve;
                if (ecParameterSpec.toString().startsWith("secp256r1")) {
                    curve = "P-256";
                } else if (ecParameterSpec.toString().startsWith("secp521r1")) {
                    curve = "P-521";
                } else if (ecParameterSpec.toString().startsWith("secp384r1")) {
                    curve = "P-384";
                } else {
                    throw new UnsupportedOperationException("Unknown curve specification: %s".formatted(ecParameterSpec.toString()));
                }
                jsonObjectBuilder.add("crv", curve);
            }
            if (this.publicKey instanceof ECPublicKey ecPublicKey) {
                if (ecPublicKey.getW().getAffineX().signum() == -1 || ecPublicKey.getW().getAffineY().signum() == -1) {
                    throw new ArithmeticException();
                }
                int fieldSize = (int) Math.ceil((double) ecPublicKey.getParams().getCurve().getField().getFieldSize() / 8);
                tracer.out().printfIndentln("fieldSize(Bytes) = %d", fieldSize);
                byte[] xBytes = JsonWebKeyUtils.alignBytes(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
                byte[] yBytes = JsonWebKeyUtils.alignBytes(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
                jsonObjectBuilder
                        .add("x", BASE64_URL_ENCODER.encodeToString(xBytes))
                        .add("y", BASE64_URL_ENCODER.encodeToString(yBytes));

            } else if (this.publicKey instanceof RSAPublicKey rsaPublicKey) {
                int keySize = rsaPublicKey.getModulus().bitLength();
                tracer.out().printfIndentln("keySize = %d", keySize);
                byte[] modulusBytes = JsonWebKeyUtils.skipSurplusZeroes(rsaPublicKey.getModulus().toByteArray(), keySize / 8);
                tracer.out().printfIndentln("octets(rsaPublicKey) = %s", JsonWebKeyUtils.formatBytes(modulusBytes));
                byte[] publicExponentBytes = JsonWebKeyUtils.skipLeadingZeroes(rsaPublicKey.getPublicExponent().toByteArray());
                tracer.out().printfIndentln("octets(publicExponentBytes) = %s", JsonWebKeyUtils.formatBytes(publicExponentBytes));
                jsonObjectBuilder
                        .add("n", BASE64_URL_ENCODER.encodeToString(modulusBytes))
                        .add("e", BASE64_URL_ENCODER.encodeToString(publicExponentBytes));
            } else {
                throw new UnsupportedOperationException();
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    /**
     * A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebPublicKey}s by wrapping a {@code PublicKey}.
     */
    public static class Builder extends JsonWebKey.Builder<Builder> {

        final PublicKey publicKey;

        /**
         * Creates the {@code JsonWebPublicKey.Builder} preconfigured with the given {@code PublicKey}.
         *
         * @param publicKey the requested {@code PublicKey}
         */
        public Builder(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        /**
         * Builds the {@code JsonWebPublicKey} with the configured parameters.
         *
         * @return the appropriately configured {@code JsonWebPublicKey} instance
         */
        @Override
        public JsonWebPublicKey build() {
            return new JsonWebPublicKey(this);
        }
    }

    /**
     * Factory method to create a {@code JsonWebPublicKey} instance from a plain {@code JsonObject}.
     *
     * @param jwkView the given {@code JsonObject}.
     * @return a {@code JsonWebPublicKey}
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    public static JsonWebPublicKey fromJson(JsonObject jwkView) throws GeneralSecurityException {
        String keyType = JsonUtils.orElseThrow(jwkView, "kty", JsonString.class).getString();
        return switch (keyType) {
            case "EC" -> {
                String curve = JsonUtils.orElseThrow(jwkView, "crv", JsonString.class).getString();
                if (curve.startsWith("secp256r1") || Objects.equals("P-256", curve)) {
                    curve = "secp256r1";
                } else if (curve.startsWith("secp521r1") || Objects.equals("P-521", curve)) {
                    curve = "secp521r1";
                } else {
                    throw new UnsupportedOperationException();
                }
                ECParameterSpec ecParameterSpec = EC_PARAMETER_SPEC_MAP.get(curve);
                BigInteger x = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "x", JsonString.class).getString()));
                BigInteger y = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "y", JsonString.class).getString()));
                ECPoint w = new ECPoint(x, y);
                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
                String kid = jwkView.getString("kid", null);
                yield JsonWebPublicKey.of(publicKey)
                        .withKid(kid)
                        .build();
            }
            case "RSA" -> {
                BigInteger n = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "n", JsonString.class).getString()));
                BigInteger e = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "e", JsonString.class).getString()));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
                String kid = jwkView.getString("kid", null);
                yield JsonWebPublicKey.of(publicKey)
                        .withKid(kid)
                        .build();
            }
            default -> throw new UnsupportedOperationException();
        };
    }
}
