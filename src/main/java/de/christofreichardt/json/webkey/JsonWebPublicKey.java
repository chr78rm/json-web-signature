package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.websignature.JWSUtils;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

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
    JsonObject toJson() {
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
        JsonWebPublicKey build() {
            return new JsonWebPublicKey(this);
        }
    }
}
