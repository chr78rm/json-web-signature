package de.christofreichardt.json.websignature;

import de.christofreichardt.json.webkey.JsonWebPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class JOSEHeader {

    final String alg;
    final String typ;
    final String kid;
    final JsonWebPublicKey jsonWebPublicKey;

    public String getAlg() {
        return alg;
    }

    public String getTyp() {
        return typ;
    }

    public String getKid() {
        return kid;
    }

    public JsonWebPublicKey getJsonWebPublicKey() {
        return jsonWebPublicKey;
    }

    public JOSEHeader(Builder builder) {
        if (!JWSBase.ALGO_MAP.containsKey(builder.alg)) {
            throw new IllegalArgumentException(String.format("Unsupported algorithm '%s'.", builder.alg));
        }
        this.alg = builder.alg;
        this.typ = builder.typ;
        if (Objects.isNull(builder.kid)) {
            if (Objects.nonNull(builder.jsonWebPublicKey)) {
                this.kid = builder.jsonWebPublicKey.getKid();
            } else {
                this.kid = null;
            }
        } else {
            if (Objects.nonNull(builder.jsonWebPublicKey)) {
                if (Objects.equals(builder.kid, builder.jsonWebPublicKey.getKid())) {
                    this.kid = builder.kid;
                } else {
                    throw new IllegalArgumentException("Ambigous kid.");
                }
            } else {
                this.kid = builder.kid;
            }
        }
        if (Objects.nonNull(builder.jsonWebPublicKey)) {
            if (Objects.equals("ES256", this.alg)) {
                if (builder.jsonWebPublicKey.getAlgorithmParameterSpec() instanceof ECParameterSpec ecParameterSpec) {
                    if (!ecParameterSpec.toString().startsWith("secp256r1")) {
                        throw new IllegalArgumentException(String.format("Inappropriate curve '%s' for algorithm '%s'.", ecParameterSpec, this.alg));
                    }
                } else {
                    throw new IllegalArgumentException("Inappropriate algorithm parameters.");
                }
                if (!Objects.equals("EC", builder.jsonWebPublicKey.getKeyType())) {
                    throw new IllegalArgumentException(String.format("Inappropriate key type '%s' for algorithm '%s'.", builder.jsonWebPublicKey.getKeyType(), this.alg));
                }
            } else if (Objects.equals("RS256", this.alg)) {
                if (!Objects.equals("RSA", builder.jsonWebPublicKey.getKeyType())) {
                    throw new IllegalArgumentException(String.format("Inappropriate key type '%s' for algorithm '%s'.", builder.jsonWebPublicKey.getKeyType(), this.alg));
                }
            } else if (Objects.equals("HS256", this.alg)) {
                throw new IllegalArgumentException("Symmetric algorithms don't use public keys.");
            }
        }
        this.jsonWebPublicKey = builder.jsonWebPublicKey;
    }

    public static Builder of (String alg) {
        return new Builder(alg);
    }

    public static class Builder {
        final String alg;
        String typ = null;
        String kid = null;
        JsonWebPublicKey jsonWebPublicKey = null;

        public Builder(String alg) {
            this.alg = alg;
        }

        public Builder withTyp(String typ) {
            this.typ = typ;
            return this;
        }

        public Builder withKid(String kid) {
            this.kid = kid;
            return this;
        }

        public Builder withJsonWebPublicKey(JsonWebPublicKey jsonWebPublicKey) {
            this.jsonWebPublicKey = jsonWebPublicKey;
            return this;
        }

        public JOSEHeader build() {
            return new JOSEHeader(this);
        }
    }

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
}
