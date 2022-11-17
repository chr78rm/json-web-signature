package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebSecretKey;

public interface SignatureBegin {
    BeforeTyp keyPair(JsonWebKeyPair jsonWebKeyPair);
    BeforeTyp secretKey(JsonWebSecretKey jsonWebSecretKey);
}
