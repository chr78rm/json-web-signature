package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonUtils;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;

public class JOSEHeader implements Traceable {

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

    public JOSEHeader(AlgorithmBuilder algorithmBuilder) {
        if (!JWSBase.ALGO_MAP.containsKey(algorithmBuilder.alg)) {
            throw new IllegalArgumentException(String.format("Unsupported algorithm '%s'.", algorithmBuilder.alg));
        }
        this.alg = algorithmBuilder.alg;
        this.typ = algorithmBuilder.typ;
        this.kid = algorithmBuilder.kid;
        this.jsonWebPublicKey = null;
    }

    public JOSEHeader(PublicKeyBuilder publicKeyBuilder) {
        this.alg = publicKeyBuilder.alg;
        this.kid = publicKeyBuilder.kid;
        this.typ = publicKeyBuilder.typ;
        this.jsonWebPublicKey = publicKeyBuilder.jsonWebPublicKey;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        JOSEHeader that = (JOSEHeader) object;
        return alg.equals(that.alg) && Objects.equals(typ, that.typ) && Objects.equals(kid, that.kid) && Objects.equals(jsonWebPublicKey, that.jsonWebPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alg, typ, kid, jsonWebPublicKey);
    }

    public static AlgorithmBuilder of(String alg) {
        return new AlgorithmBuilder(alg);
    }

    public static PublicKeyBuilder of(JsonWebPublicKey jsonWebPublicKey) {
        return new PublicKeyBuilder(jsonWebPublicKey);
    }

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

    public static class PublicKeyBuilder implements Traceable {
        static Map<String, String> ecAlgoMap = Map.of("secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)", "ES256");
        static Set<String> rsaAlgos = Set.of("RS256");

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
                    String rsaAlgo = "RS" + keysize;
                    if (!rsaAlgos.contains(rsaAlgo)) {
                        throw new IllegalArgumentException(String.format("Invalid keysize %d.", keysize));
                    }
                    return rsaAlgo;
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
