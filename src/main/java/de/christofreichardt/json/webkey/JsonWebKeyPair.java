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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;

/**
 * Convenient for the handling of key pairs in the spirit of RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
 *
 * @author Christof Reichardt
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517 (JSON Web Key)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html">RFC 7518 (JSON Web Algorithms)</a>
 */
final public class JsonWebKeyPair extends JsonWebKey {

    /**
     * Creates the default builder for a {@code JsonWebKeyPair}. Use this variant if you want to automatically create an EC key pair for curve "secp256r1".
     *
     * @return a {@link de.christofreichardt.json.webkey.JsonWebKeyPair.Builder}.
     */
    public static Builder of() {
        return new Builder();
    }

    /**
     * Creates a special builder for a {@code JsonWebKeyPair}. Use this variant if you already have a {@code KeyPair}.
     *
     * @param keyPair the provided {@code KeyPair}.
     * @return a {@link de.christofreichardt.json.webkey.JsonWebKeyPair.KeyPairBuilder}.
     */
    public static KeyPairBuilder of(KeyPair keyPair) {
        return new KeyPairBuilder(keyPair);
    }

    /**
     * Creates a special builder for a {@code JsonWebKeyPair}. Use this variant if you want to create a {@code KeyPair} from a provided {@code AlgorithmParameterSpec}.
     *
     * @param algorithmParameterSpec the provided {@code AlgorithmParameterSpec}.
     * @return a {@link de.christofreichardt.json.webkey.JsonWebKeyPair.ParameterSpecBuilder}.
     */
    public static ParameterSpecBuilder of(AlgorithmParameterSpec algorithmParameterSpec) {
        return new ParameterSpecBuilder(algorithmParameterSpec);
    }

    final KeyPair keyPair;
    final AlgorithmParameterSpec algorithmParameterSpec;

    /**
     * Returns the actual {@code KeyPair}.
     *
     * @return the actual {@code KeyPair}.
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * Returns the applied {@code AlgorithmParameterSpec}, may be null.
     *
     * @return the applied {@code AlgorithmParameterSpec}
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    JsonWebKeyPair(Builder builder) {
        super(builder.kid, builder.keyPair.getPublic().getAlgorithm());
        this.keyPair = builder.keyPair;
        if (this.keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
    }

    JsonWebKeyPair(KeyPairBuilder keyPairBuilder) {
        super(keyPairBuilder.kid, keyPairBuilder.keyPair.getPublic().getAlgorithm());
        this.keyPair = keyPairBuilder.keyPair;
        if (this.keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
    }

    JsonWebKeyPair(ParameterSpecBuilder parameterSpecBuilder) {
        super(parameterSpecBuilder.kid, parameterSpecBuilder.keyPair.getPublic().getAlgorithm());
        this.keyPair = parameterSpecBuilder.keyPair;
        if (this.keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
    }

    /**
     * Creates a {@link de.christofreichardt.json.webkey.JsonWebPublicKey} from this {@code JsonWebKeyPair}. Firstly this {@code JsonWebKeyPair} instance will be serialized
     * into a {@code JsonObject} and then {@link de.christofreichardt.json.webkey.JsonWebPublicKey#fromJson(jakarta.json.JsonObject)} will be invoked.
     *
     * @return a {@link de.christofreichardt.json.webkey.JsonWebPublicKey}
     * @throws GeneralSecurityException
     */
    public JsonWebPublicKey jsonWebPublicKey() throws GeneralSecurityException {
        return JsonWebPublicKey.fromJson(this.toJson());
    }

    /**
     * Returns a textual representation of this {@code JsonWebKeyPair}.
     *
     * @return a textual representation of this {@code JsonWebKeyPair}.
     */
    @Override
    public String toString() {
        String params = null;
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            params = ecParameterSpec.toString();
        }
        return String.format("%s[kid=%s, keyType=%s, params=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, params); // TODO: keyPair data element is missing.
    }

    /**
     * Compares this {@code JsonWebKeyPair} with another {@code JsonWebKeyPair}.
     * Compares this {@code JsonWebKeyPair} with another ensuring that it contains the same configuration. Only objects of type {@code JsonWebKeyPair} are considered, other
     * types return false.
     *
     * @param object the object to check, null returns false
     * @return true if this is equal to the other {@code JsonWebKeyPair}
     */
    @Override
    public boolean equals(Object object) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("boolean", this, "equals(Object object)");

        try {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;
            JsonWebKeyPair that = (JsonWebKeyPair) object;

            tracer.out().printfIndentln("this.keyPair.getPublic().getClass().getName() = %s, that.keyPair.getPublic().getClass().getName() = %s",
                    this.keyPair.getPublic().getClass().getName(), that.keyPair.getPublic().getClass().getName());
            tracer.out().printfIndentln("this.keyPair.getPrivate().getClass().getName() = %s, that.keyPair.getPrivate().getClass().getName() = %s",
                    this.keyPair.getPrivate().getClass().getName(), that.keyPair.getPrivate().getClass().getName());

            BigInteger privateExponent1 = null, privateExponent2 = null;
            boolean isPrivateKeyTheSame;
            if (this.keyPair.getPrivate() instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
                privateExponent1 = rsaPrivateCrtKey.getPrivateExponent();
            } else if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                privateExponent1 = rsaPrivateKey.getPrivateExponent();
            }
            if (that.keyPair.getPrivate() instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
                privateExponent2 = rsaPrivateCrtKey.getPrivateExponent();
            } else if (that.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                privateExponent2 = rsaPrivateKey.getPrivateExponent();
            }
            if (Objects.nonNull(privateExponent1) && Objects.nonNull(privateExponent2)) {
                isPrivateKeyTheSame = privateExponent1.equals(privateExponent2);
            } else if (Objects.nonNull(privateExponent1)) {
                isPrivateKeyTheSame = false;
            } else if (Objects.nonNull(privateExponent2)) {
                isPrivateKeyTheSame = false;
            } else {
                isPrivateKeyTheSame = this.keyPair.getPrivate().equals(that.keyPair.getPrivate());
            }

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
            return Objects.equals(this.keyPair.getPublic(), that.keyPair.getPublic())
                    && isPrivateKeyTheSame
                    && isAlgoTheSame
                    && Objects.equals(this.kid, that.kid)
                    && Objects.equals(this.keyType, that.keyType);
        } finally {
            tracer.wayout();
        }
    }

    /**
     * A hash code for this {@code JsonWebKeyPair}.
     *
     * @return a suitable hash code.
     */
    @Override
    public int hashCode() {
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                return Objects.hash(this.keyPair.getPublic(), rsaPrivateKey.getPrivateExponent(), ecParameterSpec.toString(), this.kid, this.keyType);
            } else {
                return Objects.hash(this.keyPair.getPublic(), this.keyPair.getPrivate(), ecParameterSpec.toString(), this.kid, this.keyType);
            }
        } else {
            if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                return Objects.hash(this.keyPair.getPublic(), rsaPrivateKey.getPrivateExponent(), this.algorithmParameterSpec, this.kid, this.keyType);
            } else {
                return Objects.hash(this.keyPair.getPublic(), this.keyPair.getPrivate(), this.algorithmParameterSpec, this.kid, this.keyType);
            }
        }
    }

    /**
     * Converts this {@code JsonWebKeyPair} into a plain {@code JsonObject}.
     *
     * @return a {@code JsonObject} corresponding to this {@code JsonWebKeyPair}.
     * @see <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonobject">JsonObject (Jakarta EE Platform API)</a>
     */
    @Override
    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(super.toJson());

            if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
                jsonObjectBuilder.add("crv", ecParameterSpec.toString());
            }

            if (this.keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
                if (ecPublicKey.getW().getAffineX().signum() == -1 || ecPublicKey.getW().getAffineY().signum() == -1) {
                    throw new ArithmeticException();
                }
                int fieldSize = ecPublicKey.getParams().getCurve().getField().getFieldSize() / 8;
                byte[] xBytes = JsonWebKeyUtils.alignBytes(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
                byte[] yBytes = JsonWebKeyUtils.alignBytes(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
                jsonObjectBuilder
                        .add("x", BASE64_URL_ENCODER.encodeToString(xBytes))
                        .add("y", BASE64_URL_ENCODER.encodeToString(yBytes));

            } else if (this.keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
                int keySize = rsaPublicKey.getModulus().bitLength();
                tracer.out().printfIndentln("keySize = %d", keySize);
                byte[] modulusBytes = JsonWebKeyUtils.skipSurplusZeroes(rsaPublicKey.getModulus().toByteArray(), keySize / 8);
                tracer.out().printfIndentln("#(modulusBytes) = %d, octets(modulusBytes) = %s", modulusBytes.length, JsonWebKeyUtils.formatBytes(modulusBytes));
                byte[] publicExponentBytes = JsonWebKeyUtils.skipLeadingZeroes(rsaPublicKey.getPublicExponent().toByteArray());
                tracer.out().printfIndentln("octets(publicExponentBytes) = %s", JsonWebKeyUtils.formatBytes(publicExponentBytes));
                jsonObjectBuilder
                        .add("n", BASE64_URL_ENCODER.encodeToString(modulusBytes))
                        .add("e", BASE64_URL_ENCODER.encodeToString(publicExponentBytes));
            } else {
                throw new UnsupportedOperationException();
            }

            if (this.keyPair.getPrivate() instanceof ECPrivateKey ecPrivateKey) {
                BigInteger order = ecPrivateKey.getParams().getOrder();
                byte[] dBytes = JsonWebKeyUtils.alignBytes(ecPrivateKey.getS().toByteArray(), order.bitLength() / 8);
                jsonObjectBuilder.add("d", BASE64_URL_ENCODER.encodeToString(dBytes));
            } else if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                byte[] privateExponentBytes = JsonWebKeyUtils.skipLeadingZeroes(rsaPrivateKey.getPrivateExponent().toByteArray());
                tracer.out().printfIndentln("octets(privateExponentBytes) = %s", JsonWebKeyUtils.formatBytes(privateExponentBytes));
                jsonObjectBuilder.add("d", BASE64_URL_ENCODER.encodeToString(privateExponentBytes));
            } else {
                throw new UnsupportedOperationException();
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    /**
     * A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebKeyPair}s by internally generating
     * an EC key pair for the curve "secp256r1".
     */
    public static class Builder extends JsonWebKey.Builder<Builder> {

        KeyPair keyPair;
        final AlgorithmParameterSpec algorithmGenParameterSpec = new ECGenParameterSpec("secp256r1");

        @Override
        public JsonWebKeyPair build() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(algorithmGenParameterSpec);
            this.keyPair = keyPairGenerator.generateKeyPair();

            return new JsonWebKeyPair(this);
        }
    }

    /**
     * A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebKeyPair}s by provided {@code KeyPair}s.
     */
    public static class KeyPairBuilder extends JsonWebKey.Builder<KeyPairBuilder> {
        final KeyPair keyPair;

        public KeyPairBuilder(KeyPair keyPair) {
            this.keyPair = keyPair;
        }

        @Override
        public JsonWebKeyPair build() {
            return new JsonWebKeyPair(this);
        }
    }

    /**
     * A {@link de.christofreichardt.json.webkey.JsonWebKey.Builder} for building {@code JsonWebKeyPair}s by a provided {@code AlgorithmParameterSpec}.
     * The {@code AlgorithmParameterSpec} object will internally be used to create an appropriate {@code  KeyPair}.
     */
    public static class ParameterSpecBuilder extends JsonWebKey.Builder<ParameterSpecBuilder> {
        final AlgorithmParameterSpec algorithmParameterSpec;
        KeyPair keyPair;

        public ParameterSpecBuilder(AlgorithmParameterSpec algorithmParameterSpec) {
            this.algorithmParameterSpec = algorithmParameterSpec;
        }

        @Override
        public JsonWebKeyPair build() throws GeneralSecurityException {
            KeyPairGenerator keyPairGenerator;
            if (this.algorithmParameterSpec instanceof ECGenParameterSpec) {
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
            } else if (algorithmParameterSpec instanceof RSAKeyGenParameterSpec) {
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            } else {
                throw new InvalidAlgorithmParameterException();
            }
            keyPairGenerator.initialize(algorithmParameterSpec);
            this.keyPair = keyPairGenerator.generateKeyPair();

            return new JsonWebKeyPair(this);
        }
    }

    /**
     * Factory method to create a {@code JsonWebKeyPair} instance from a plain {@code JsonObject}.
     *
     * @param jwkView the given {@code JsonObject}.
     * @return a {@code JsonWebKeyPair}
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    public static JsonWebKeyPair fromJson(JsonObject jwkView) throws GeneralSecurityException {
        String keyType = JsonUtils.orElseThrow(jwkView, "kty", JsonString.class).getString();

        return switch (keyType) {
            case "EC" -> {
                String curve = JsonUtils.orElseThrow(jwkView, "crv", JsonString.class).getString();
                if (!curve.startsWith("secp256r1")) {
                    throw new UnsupportedOperationException();
                }
                ECParameterSpec ecParameterSpec = EC_PARAMETER_SPEC_MAP.get("secp256r1");
                BigInteger x = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "x", JsonString.class).getString()));
                BigInteger y = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "y", JsonString.class).getString()));
                BigInteger d = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "d", JsonString.class).getString()));
                ECPoint w = new ECPoint(x, y);
                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
                ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
                PrivateKey privateKey = keyFactory.generatePrivate(ecPrivateKeySpec);
                KeyPair keyPair = new KeyPair(publicKey, privateKey);
                String kid = jwkView.getString("kid", null);
                yield JsonWebKeyPair.of(keyPair)
                        .withKid(kid)
                        .build();
            }
            case "RSA" -> {
                BigInteger n = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "n", JsonString.class).getString()));
                BigInteger e = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "e", JsonString.class).getString()));
                BigInteger d = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "d", JsonString.class).getString()));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
                RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
                PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
                KeyPair keyPair = new KeyPair(publicKey, privateKey);
                String kid = jwkView.getString("kid", null);
                yield JsonWebKeyPair.of(keyPair)
                        .withKid(kid)
                        .build();
            }
            default -> throw new UnsupportedOperationException();
        };
    }
}
