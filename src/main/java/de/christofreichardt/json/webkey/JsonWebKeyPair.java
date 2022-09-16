package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.websignature.JWSUtils;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Objects;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

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
}
