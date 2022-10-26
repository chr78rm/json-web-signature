package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.JsonUtils;
import de.christofreichardt.json.websignature.JWSUtils;
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
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;

final public class JsonWebPublicKey extends JsonWebKey {

    public static Builder of(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    final PublicKey publicKey;
    final AlgorithmParameterSpec algorithmParameterSpec;

    public JsonWebPublicKey(Builder builder) {
        super(builder.kid, builder.publicKey.getAlgorithm());
        this.publicKey = builder.publicKey;
        if (this.publicKey instanceof ECPublicKey ecPublicKey) {
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

    @Override
    public int hashCode() {
        if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
            return Objects.hash(this.publicKey, ecParameterSpec.toString(), this.kid, this.keyType);
        } else {
            return Objects.hash(this.publicKey, this.algorithmParameterSpec, this.kid, this.keyType);
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
            if (this.publicKey instanceof ECPublicKey ecPublicKey) {
                if (ecPublicKey.getW().getAffineX().signum() == -1 || ecPublicKey.getW().getAffineY().signum() == -1) {
                    throw new ArithmeticException();
                }
                int fieldSize = ecPublicKey.getParams().getCurve().getField().getFieldSize() / 8;
                byte[] xBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
                byte[] yBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
                jsonObjectBuilder
                        .add("x", BASE64_URL_ENCODER.encodeToString(xBytes))
                        .add("y", BASE64_URL_ENCODER.encodeToString(yBytes));

            } else if (this.publicKey instanceof RSAPublicKey rsaPublicKey) {
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

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        final PublicKey publicKey;

        public Builder(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public JsonWebPublicKey build() {
            return new JsonWebPublicKey(this);
        }
    }

    public static JsonWebPublicKey fromJson(JsonObject jwkView) throws GeneralSecurityException {
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
                BigInteger n = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "n", JsonString.class).getString()));
                BigInteger e = new BigInteger(1, BASE64_URL_DECODER.decode(JsonUtils.getOrElseThrow(jwkView, "e", JsonString.class).getString()));
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
