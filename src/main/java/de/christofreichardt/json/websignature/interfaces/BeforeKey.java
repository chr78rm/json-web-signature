package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public interface BeforeKey {
    ValidationEnd key(PublicKey publicKey);
    ValidationEnd key(SecretKey secretKey);
    ValidationEnd key(JsonWebPublicKey jsonWebPublicKey);
    ValidationEnd key(JsonWebSecretKey jsonWebSecretKey);
}
