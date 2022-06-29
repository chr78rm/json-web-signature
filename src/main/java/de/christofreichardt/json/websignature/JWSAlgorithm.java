package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.Traceable;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 *
 * @author Christof Reichardt
 */
public interface JWSAlgorithm extends Traceable {
    void init(Key key) throws GeneralSecurityException;
    void update(byte[] data) throws GeneralSecurityException;
    byte[] signature() throws GeneralSecurityException;
    boolean verify(byte[] signature) throws GeneralSecurityException;
    String algorithm();
}
