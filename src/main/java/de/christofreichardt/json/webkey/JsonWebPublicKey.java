package de.christofreichardt.json.webkey;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

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
        return String.format("%s[kid=%s, keyType=%S, params=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, params);
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
