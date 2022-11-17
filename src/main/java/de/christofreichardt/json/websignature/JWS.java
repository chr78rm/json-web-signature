package de.christofreichardt.json.websignature;

import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import de.christofreichardt.json.websignature.interfaces.BeforeKid;
import de.christofreichardt.json.websignature.interfaces.BeforePayload;
import de.christofreichardt.json.websignature.interfaces.BeforeTyp;
import de.christofreichardt.json.websignature.interfaces.SignatureBegin;
import de.christofreichardt.json.websignature.interfaces.SignatureEnd;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Objects;
import javax.json.JsonObject;

public class JWS {
    private JWS() {
    }

    public static SignatureBegin createSignature() {
        return new Signature();
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
        public BeforeTyp keyPair(JsonWebKeyPair jsonWebKeyPair) {
            this.jsonWebKey = jsonWebKeyPair;
            return this;
        }

        @Override
        public BeforeTyp secretKey(JsonWebSecretKey jsonWebSecretKey) {
            this.jsonWebKey = jsonWebSecretKey;
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
}
