package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.KeyPair;
import javax.crypto.SecretKey;

public interface SignatureBegin {
    BeforeHeader webkey(JsonWebKeyPair jsonWebKeyPair);
    BeforeHeader webkey(JsonWebSecretKey jsonWebSecretKey);
    BeforeHeader key(KeyPair keyPair);
    BeforeHeader key(SecretKey secretKey);
}
