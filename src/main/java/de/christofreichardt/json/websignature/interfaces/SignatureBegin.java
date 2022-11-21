package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.KeyPair;
import javax.crypto.SecretKey;

public interface SignatureBegin {
    BeforeTyp webkey(JsonWebKeyPair jsonWebKeyPair);
    BeforeTyp webkey(JsonWebSecretKey jsonWebSecretKey);
    BeforeTyp key(KeyPair keyPair);
    BeforeTyp key(SecretKey secretKey);
}
