package de.christofreichardt.json.webkey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Objects;

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
        return String.format("%s[kid=%s, keyType=%S, params=%s]", this.getClass().getSimpleName(), this.kid, this.keyType, params);
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
