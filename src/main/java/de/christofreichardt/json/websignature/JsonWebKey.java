package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

public class JsonWebKey implements Traceable {

    final PublicKey publicKey;
    final PrivateKey privateKey;
    final String keyType;
    final String kid;
    final AlgorithmParameterSpec algorithmParameterSpec;

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getKeyType() {
        return this.keyType;
    }

    public String getKid() {
        return this.kid;
    }

    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return this.algorithmParameterSpec;
    }

    public JsonWebKey(Builder builder) {
        this.publicKey = builder.publicKey;
        this.privateKey = builder.privateKey;
        if (this.publicKey instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
        this.keyType = this.publicKey.getAlgorithm();
        this.kid = builder.kid;
    }

    static Builder of(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    public static class Builder {
        final PublicKey publicKey;
        final PrivateKey privateKey;
        String kid = null;

        public Builder(PublicKey publicKey) {
            this.publicKey = publicKey;
            this.privateKey = null;
        }

        public Builder(KeyPair keyPair) {
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
        }

        public Builder withKid(String kid) {
            this.kid = kid;
            return this;
        }

        JsonWebKey build() {
            return new JsonWebKey(this);
        }
    }

    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");
        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder()
                    .add("kty", this.keyType);
            if (this.kid != null) {
                jsonObjectBuilder.add("kid", this.kid);
            }
            if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
                jsonObjectBuilder.add("crv", ecParameterSpec.toString());
            }
            if (this.publicKey instanceof ECPublicKey ecPublicKey) {
                byte[] xBytes = ecPublicKey.getW().getAffineX().toByteArray();
                jsonObjectBuilder
                        .add("x", ecPublicKey.getW().getAffineX())
                        .add("y", ecPublicKey.getW().getAffineY());

            }
            if (this.publicKey instanceof RSAPublicKey rsaPublicKey) {
                jsonObjectBuilder
                        .add("n", rsaPublicKey.getModulus())
                        .add("e", rsaPublicKey.getPublicExponent());
            }
            if (this.privateKey instanceof ECPrivateKey ecPrivateKey) {
                jsonObjectBuilder.add("d", ecPrivateKey.getS());
            }
            if (this.privateKey instanceof RSAPrivateKey rsaPrivateKey) {
                jsonObjectBuilder.add("d", rsaPrivateKey.getPrivateExponent());
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
