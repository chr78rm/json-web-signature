package de.christofreichardt.json.websignature;

import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKid;
import de.christofreichardt.json.websignature.interfaces.BeforePayload;
import de.christofreichardt.json.websignature.interfaces.BeforeTyp;
import de.christofreichardt.json.websignature.interfaces.SignatureBegin;
import de.christofreichardt.json.websignature.interfaces.SignatureEnd;
import de.christofreichardt.json.websignature.interfaces.ValidationBegin;
import de.christofreichardt.json.websignature.interfaces.ValidationEnd;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.json.JsonObject;

public class JWS {
    private JWS() {
    }

    public static SignatureBegin createSignature() {
        return new Signature();
    }

    public static ValidationBegin createValidator() {
        return new Validator();
    }

    private static class Signature implements SignatureBegin, BeforePayload, BeforeTyp, BeforeKid, SignatureEnd {

        JsonWebKey jsonWebKey;
        JsonObject payload;
        String kid;
        String typ;

        @Override
        public SignatureEnd payload(JsonObject payload) {
            this.payload = payload;
            return this;
        }

        @Override
        public BeforeTyp webkey(JsonWebKeyPair jsonWebKeyPair) {
            this.jsonWebKey = jsonWebKeyPair;
            return this;
        }

        @Override
        public BeforeTyp webkey(JsonWebSecretKey jsonWebSecretKey) {
            this.jsonWebKey = jsonWebSecretKey;
            return this;
        }

        @Override
        public BeforeTyp key(KeyPair keyPair) {
            this.jsonWebKey = JsonWebKeyPair.of(keyPair)
                    .build();
            return this;
        }

        @Override
        public BeforeTyp key(SecretKey secretKey) {
            this.jsonWebKey = JsonWebSecretKey.of(secretKey)
                    .build();
            return this;
        }

        @Override
        public JWSCompactSerialization sign() throws GeneralSecurityException {
            JWSCompactSerialization compactSerialization;
            JOSEHeader joseHeader;
            if (this.jsonWebKey instanceof JsonWebSecretKey jsonWebSecretKey) {
                joseHeader = JOSEHeader.of(jsonWebSecretKey.getAlgorithm())
                        .withKid(this.kid)
                        .withTyp(this.typ)
                        .build();
                JWSSigner jwsSigner = new JWSSigner(joseHeader.toJson(), this.payload);
                compactSerialization = jwsSigner.sign(jsonWebSecretKey.getSecretKey());
            } else if (this.jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair) {
                joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .withTyp(this.typ)
                        .build();
                JWSSigner jwsSigner = new JWSSigner(joseHeader.toJson(), this.payload);
                compactSerialization = jwsSigner.sign(jsonWebKeyPair.getKeyPair().getPrivate());
            } else {
                throw new UnsupportedOperationException();
            }

            return compactSerialization;
        }

        @Override
        public BeforePayload kid(String kid) {
            if (!Objects.equals(this.jsonWebKey.getKid(), kid)) {
                throw new IllegalArgumentException("Ambigous kids.");
            }
            this.kid = kid;
            return this;
        }

        @Override
        public BeforeKid typ(String typ) {
            this.typ = typ;
            return this;
        }
    }

    private static class Validator implements ValidationBegin, BeforeKey, ValidationEnd {

        JWSCompactSerialization compactSerialization;
        Key key;

        @Override
        public ValidationEnd key(PublicKey publicKey) {
            this.key = publicKey;
            return this;
        }

        @Override
        public ValidationEnd key(SecretKey secretKey) {
            this.key = secretKey;
            return this;
        }

        @Override
        public ValidationEnd key(JsonWebPublicKey jsonWebPublicKey) {
            this.key = jsonWebPublicKey.getPublicKey();
            return this;
        }

        @Override
        public ValidationEnd key(JsonWebSecretKey jsonWebSecretKey) {
            this.key = jsonWebSecretKey.getSecretKey();
            return this;
        }

        @Override
        public BeforeKey compactSerialization(JWSCompactSerialization compactSerialization) {
            this.compactSerialization = compactSerialization;
            return this;
        }

        @Override
        public boolean validate() throws GeneralSecurityException {
            JWSValidator jwsValidator = new JWSValidator(this.compactSerialization);
            return jwsValidator.validate(this.key);
        }
    }
}
