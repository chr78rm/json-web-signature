package de.christofreichardt.json.webkey;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

final public class JsonWebSecretKey extends JsonWebKey {

    final static public Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256");

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
        return String.format("%s[kid=%s, keyType=%s, algorithm=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, this.secretKey.getAlgorithm());
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        SecretKey secretKey;
        String algorithm = "HmacSHA256";
        int keysize = 256;

        public Builder withSecretKey(SecretKey secretKey) throws InvalidKeyException {
            if (!JDK2JSON_ALGO_MAP.containsKey(this.secretKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            this.secretKey = secretKey;
            return this;
        }

        public Builder withKeysize(int keysize) {
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
