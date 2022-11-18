package de.christofreichardt.json.websignature.interfaces;

import java.security.GeneralSecurityException;

public interface ValidationEnd {
    boolean validate() throws GeneralSecurityException;
}
