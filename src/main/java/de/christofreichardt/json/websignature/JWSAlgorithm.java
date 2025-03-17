/*
 * Copyright (C) 2022, Christof Reichardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.Traceable;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * All algorithm classes used for signing or validating must implement this interface. The methods below are acting as adapters
 * between the instances responsible for signing (or rather validating) and the cryptographic algorithms provided by the
 * Java platform.
 *
 * @author Christof Reichardt
 */
public interface JWSAlgorithm extends Traceable {
    /**
     * Initialises the underlying algorithm provided by the Java platform with the given key.
     *
     * @param key the cryptographic key used for signing or validating.
     * @throws GeneralSecurityException if something goes wrong during the initialization.
     */
    void init(Key key) throws GeneralSecurityException;

    /**
     * Hands over the given bytes to the underlying algorithm provided by the Java platform.
     *
     * @param data the data to be signed or to be validated.
     * @throws GeneralSecurityException if something goes wrong during the update, e.g. the underlying algorithm hasn't been properly initialized.
     */
    void update(byte[] data) throws GeneralSecurityException;

    /**
     * Requests a signature from the underlying algorithm for the delivered bytes.
     *
     * @return the signature bytes
     * @throws GeneralSecurityException if the underlying algorithm couldn't process the delivered data for various reasons.
     */
    byte[] signature() throws GeneralSecurityException;

    /**
     * Requests the validation of the delivered data agianst the given signature.
     *
     * @param signature the signature bytes.
     * @return indicates if the signature has been valid.
     * @throws GeneralSecurityException if the underlying algorithm couldn't process the delivered data for various reasons.
     */
    boolean verify(byte[] signature) throws GeneralSecurityException;

    /**
     * Returns the name of the underlying algorithm object.
     * @return the name of the underlying algorithm object.
     */
    String algorithm();

    /**
     * Optional post-processing of the signature bytes, for example the signature bytes might be DER encoded and RFC 7515 or rather RFC 7518
     * require a different format.
     *
     * @param signature the signature bytes.
     * @return the optionally processed signature bytes
     */
    String postSigning(byte[] signature);

    /**
     * Optional pre-processing of the to be validated signature bytes, for example the verifying algorithm instance given by the Java runtime might
     * require DER encoded signature bytes.
     *
     * @param signature the signature bytes.
     * @return the optionally processed signature bytes
     */
    byte[] preValidating(byte[] signature);
}
