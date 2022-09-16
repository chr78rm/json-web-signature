package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.websignature.JWSUtils;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

final public class JsonWebSecretKey extends JsonWebKey {

    final static public Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256", "HmacSHA512", "HS512");

    public static Builder of() {
        return new Builder();
    }

    final SecretKey secretKey;
    final String algorithm;

    public JsonWebSecretKey(Builder builder) {
        super(builder.kid, "oct");
        this.secretKey = builder.secretKey;
        this.algorithm = JDK2JSON_ALGO_MAP.get(this.secretKey.getAlgorithm());
    }

    @Override
    public String toString() {
        return String.format("%s[kid=%s, keyType=%s, algorithm=%s, keysize=%d]", this.getClass().getSimpleName(),
                this.kid, this.keyType, this.secretKey.getAlgorithm(), Objects.nonNull(this.secretKey.getEncoded()) ? this.secretKey.getEncoded().length * 8 : -1);
    }

    @Override
    JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(super.toJson());
            tracer.out().printfIndentln("octets(secretKey) = %s", JWSUtils.formatBytes(this.secretKey.getEncoded()));
            jsonObjectBuilder.add("k", BASE64_URL_ENCODER.encodeToString(this.secretKey.getEncoded()));
            jsonObjectBuilder.add("alg", this.algorithm);

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        SecretKey secretKey;
        String algorithm = "HmacSHA256";
        int keysize = 256;

        public Builder withSecretKey(SecretKey secretKey) throws InvalidKeyException {
            if (!JDK2JSON_ALGO_MAP.containsKey(secretKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            this.secretKey = secretKey;
            return this;
        }

        public Builder withKeysize(int keysize) {
            if (Objects.nonNull(this.secretKey)) {
                throw new IllegalStateException();
            }
            this.keysize = keysize;
            return this;
        }

        public Builder withAlgorithm(String algorithm) throws NoSuchAlgorithmException {
            if (Objects.nonNull(this.secretKey)) {
                throw new IllegalStateException();
            }
            if (!JDK2JSON_ALGO_MAP.containsKey(algorithm)) {
                throw new NoSuchAlgorithmException();
            }
            this.algorithm = algorithm;
            return this;
        }

        @Override
        JsonWebSecretKey build() throws NoSuchAlgorithmException {
            if (Objects.isNull(this.secretKey)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(this.algorithm);
                keyGenerator.init(this.keysize);
                this.secretKey = keyGenerator.generateKey();
            }
            return new JsonWebSecretKey(this);
        }
    }
}
