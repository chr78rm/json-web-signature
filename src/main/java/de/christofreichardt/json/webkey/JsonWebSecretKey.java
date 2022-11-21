package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.json.JsonUtils;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;

final public class JsonWebSecretKey extends JsonWebKey {

    final static public Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256", "HmacSHA512", "HS512");
    final static public Map<String, String> JSON2JDK_ALGO_MAP = new HashMap<>();

    static {
        JDK2JSON_ALGO_MAP.forEach((key, value) -> JSON2JDK_ALGO_MAP.put(value, key));
    }

    public static Builder of() {
        return new Builder();
    }

    public static SecretKeyBuilder of(SecretKey secretKey) {
        return new SecretKeyBuilder(secretKey);
    }

    final SecretKey secretKey;
    final String algorithm;

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public JsonWebSecretKey(Builder builder) {
        super(builder.kid, "oct");
        this.secretKey = builder.secretKey;
        this.algorithm = JDK2JSON_ALGO_MAP.get(this.secretKey.getAlgorithm());
    }

    public JsonWebSecretKey(SecretKeyBuilder secretKeyBuilder) {
        super(secretKeyBuilder.kid, "oct");
        this.secretKey = secretKeyBuilder.secretKey;
        this.algorithm = JDK2JSON_ALGO_MAP.get(this.secretKey.getAlgorithm());
    }

    @Override
    public String toString() {
        return String.format("%s[kid=%s, keyType=%s, algorithm=%s, keysize=%d]", this.getClass().getSimpleName(),
                this.kid, this.keyType, this.secretKey.getAlgorithm(), Objects.nonNull(this.secretKey.getEncoded()) ? this.secretKey.getEncoded().length * 8 : -1);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        JsonWebSecretKey that = (JsonWebSecretKey) object;

        return Objects.equals(this.secretKey.getAlgorithm(), that.secretKey.getAlgorithm())
                && MessageDigest.isEqual(this.secretKey.getEncoded(), that.secretKey.getEncoded())
                && Objects.equals(this.kid, that.kid)
                && Objects.equals(this.keyType, that.keyType);
    }

    @Override
    public int hashCode() {
        int hashCode = 0;
        for (int i = 0; i < this.secretKey.getEncoded().length; i++) {
            hashCode += this.secretKey.getEncoded()[i] * i;
        }

        return Objects.hash(this.algorithm, this.kid, this.keyType) ^ hashCode;
    }

    @Override
    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(super.toJson());
            tracer.out().printfIndentln("octets(secretKey) = %s", JsonWebKeyUtils.formatBytes(this.secretKey.getEncoded()));
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

        public Builder withKeysize(int keysize) {
            this.keysize = keysize;
            return this;
        }

        public Builder withAlgorithm(String algorithm) throws NoSuchAlgorithmException {
            if (!JDK2JSON_ALGO_MAP.containsKey(algorithm)) {
                throw new NoSuchAlgorithmException();
            }
            this.algorithm = algorithm;
            return this;
        }

        @Override
        public JsonWebSecretKey build() throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(this.algorithm);
            keyGenerator.init(this.keysize);
            this.secretKey = keyGenerator.generateKey();
            return new JsonWebSecretKey(this);
        }
    }

    public static class SecretKeyBuilder extends JsonWebKey.Builder<SecretKeyBuilder> {
        final SecretKey secretKey;

        public SecretKeyBuilder(SecretKey secretKey) throws IllegalArgumentException {
            if (!JDK2JSON_ALGO_MAP.containsKey(secretKey.getAlgorithm())) {
                throw new IllegalArgumentException();
            }
            this.secretKey = secretKey;
        }

        @Override
        public JsonWebSecretKey build() {
            return new JsonWebSecretKey(this);
        }
    }

    public static JsonWebSecretKey fromJson(JsonObject jwkView) throws GeneralSecurityException {
        String keyType = JsonUtils.orElseThrow(jwkView, "kty", JsonString.class).getString();
        if (!keyType.equals("oct")) {
            throw new UnsupportedOperationException();
        }
        byte[] bytes = BASE64_URL_DECODER.decode(JsonUtils.orElseThrow(jwkView, "k", JsonString.class).getString());
        String algorithm = JsonUtils.orElseThrow(jwkView, "alg", JsonString.class).getString();
        if (!JSON2JDK_ALGO_MAP.containsKey(algorithm)) {
            throw new NoSuchAlgorithmException();
        }
        algorithm = JSON2JDK_ALGO_MAP.get(algorithm);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, algorithm);
        String kid = jwkView.getString("kid", null);

        return JsonWebSecretKey.of(secretKeySpec)
                .withKid(kid)
                .build();
    }
}
