package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.websignature.JWSCompactSerialization;
import java.security.GeneralSecurityException;

public interface SignatureEnd {
    JWSCompactSerialization sign() throws GeneralSecurityException;
}
