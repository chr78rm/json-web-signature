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
    void update(byte[] data);
    byte[] signature();
    boolean verify(byte[] signature);
    String algorithm();
}
