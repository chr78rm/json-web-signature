package de.christofreichardt.json.websignature.interfaces;

import java.security.PublicKey;
import javax.crypto.SecretKey;

public interface BeforeKey {
    ValidationEnd key(PublicKey publicKey);
    ValidationEnd key(SecretKey secretKey);
}
