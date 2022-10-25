package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.JsonUtils;
import de.christofreichardt.json.websignature.JWSUtils;
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
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;

final public class JsonWebKeyPair extends JsonWebKey {

    public static Builder of() {
        return new Builder();
    }

    final KeyPair keyPair;
    final AlgorithmParameterSpec algorithmParameterSpec;

    public JsonWebKeyPair(Builder builder) {
        super(builder.kid, builder.keyPair.getPublic().getAlgorithm());
        this.keyPair = builder.keyPair;
        if (this.keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
    }

    @Override
    public String toString() {
        String params = null;
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            params = ecParameterSpec.toString();
        }
        return String.format("%s[kid=%s, keyType=%s, params=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, params);
    }

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
                byte[] xBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
                byte[] yBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
                jsonObjectBuilder
                        .add("x", BASE64_URL_ENCODER.encodeToString(xBytes))
                        .add("y", BASE64_URL_ENCODER.encodeToString(yBytes));

            } else if (this.keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
                int keySize = rsaPublicKey.getModulus().bitLength();
                tracer.out().printfIndentln("keySize = %d", keySize);
                byte[] modulusBytes = JWSUtils.skipSurplusZeroes(rsaPublicKey.getModulus().toByteArray(), keySize / 8);
                tracer.out().printfIndentln("octets(rsaPublicKey) = %s", JWSUtils.formatBytes(modulusBytes));
                byte[] publicExponentBytes = JWSUtils.skipLeadingZeroes(rsaPublicKey.getPublicExponent().toByteArray());
                tracer.out().printfIndentln("octets(publicExponentBytes) = %s", JWSUtils.formatBytes(publicExponentBytes));
                jsonObjectBuilder
                        .add("n", BASE64_URL_ENCODER.encodeToString(modulusBytes))
                        .add("e", BASE64_URL_ENCODER.encodeToString(publicExponentBytes));
            } else {
                throw new UnsupportedOperationException();
            }

            if (this.keyPair.getPrivate() instanceof ECPrivateKey ecPrivateKey) {
                BigInteger order = ecPrivateKey.getParams().getOrder();
                byte[] dBytes = JWSUtils.alignBytes(ecPrivateKey.getS().toByteArray(), order.bitLength() / 8);
                jsonObjectBuilder.add("d", BASE64_URL_ENCODER.encodeToString(dBytes));
            } else if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                byte[] privateExponentBytes = JWSUtils.skipLeadingZeroes(rsaPrivateKey.getPrivateExponent().toByteArray());
                tracer.out().printfIndentln("octets(privateExponentBytes) = %s", JWSUtils.formatBytes(privateExponentBytes));
                jsonObjectBuilder.add("d", BASE64_URL_ENCODER.encodeToString(privateExponentBytes));
            } else {
                throw new UnsupportedOperationException();
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        KeyPair keyPair;
        AlgorithmParameterSpec algorithmGenParameterSpec = new ECGenParameterSpec("secp256r1");

        public Builder withKeyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
            if (this.keyPair.getPrivate() instanceof ECPrivateKey ecPrivateKey) {
                this.algorithmGenParameterSpec = ecPrivateKey.getParams();
            } else if (this.keyPair.getPrivate() instanceof RSAPrivateKey rsaPrivateKey) {
                this.algorithmGenParameterSpec = rsaPrivateKey.getParams();
            }
            return this;
        }

        public Builder withAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec) {
            if (Objects.nonNull(this.keyPair)) {
                throw new IllegalStateException();
            }
            if (!(algorithmParameterSpec instanceof ECGenParameterSpec) && !(algorithmParameterSpec instanceof RSAKeyGenParameterSpec)) {
                throw new IllegalArgumentException();
            }
            this.algorithmGenParameterSpec = algorithmParameterSpec;
            return this;
        }

        @Override
        JsonWebKeyPair build() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
            if (Objects.isNull(this.keyPair)) {
                KeyPairGenerator keyPairGenerator;
                if (this.algorithmGenParameterSpec instanceof ECGenParameterSpec) {
                    keyPairGenerator = KeyPairGenerator.getInstance("EC");
                } else if (algorithmGenParameterSpec instanceof RSAKeyGenParameterSpec) {
                    keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                } else {
                    throw new InvalidAlgorithmParameterException();
                }
                keyPairGenerator.initialize(algorithmGenParameterSpec);
                this.keyPair = keyPairGenerator.generateKeyPair();
            }

            return new JsonWebKeyPair(this);
        }
    }

    public static JsonWebKeyPair fromJson(JsonObject jwkView) throws GeneralSecurityException {
        String keyType = JsonUtils.getOrElseThrow(jwkView, "kty", JsonString.class).getString();

        return switch (keyType) {
            case "EC" -> {
                String curve = JsonUtils.getOrElseThrow(jwkView, "crv", JsonString.class).getString();
                if (!curve.startsWith("secp256r1")) {
                    throw new UnsupportedOperationException();
                }
                ECParameterSpec ecParameterSpec = EC_PARAMETER_SPEC_MAP.get("secp256r1");
                BigInteger x = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "x", JsonString.class).getString()));
                BigInteger y = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "y", JsonString.class).getString()));
                BigInteger d = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "d", JsonString.class).getString()));
                ECPoint w = new ECPoint(x, y);
                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
                ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
                PrivateKey privateKey = keyFactory.generatePrivate(ecPrivateKeySpec);
                KeyPair keyPair = new KeyPair(publicKey, privateKey);
                String kid = jwkView.getString("kid", null);
                yield JsonWebKeyPair.of()
                        .withKeyPair(keyPair)
                        .withKid(kid)
                        .build();
            }
            case "RSA" -> {
                BigInteger n = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "n", JsonString.class).getString()));
                BigInteger e = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "e", JsonString.class).getString()));
                BigInteger d = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "d", JsonString.class).getString()));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
                RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
                PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
                KeyPair keyPair = new KeyPair(publicKey,privateKey);
                String kid = jwkView.getString("kid", null);
                yield JsonWebKeyPair.of()
                        .withKeyPair(keyPair)
                        .withKid(kid)
                        .build();
            }
            default -> throw new UnsupportedOperationException();
        };
    }
}
