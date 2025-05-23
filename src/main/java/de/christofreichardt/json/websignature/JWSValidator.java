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

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * Low level class for the validating JSON web signatures. Subject to change. Do not use. The preferred entry point is the Fluent API.
 *
 * @author Christof Reichardt
 */
public class JWSValidator extends JWSBase implements Traceable {

    final byte[] signatureOctets;

    /**
     * Creates a {@code JWSValidator} by taking a JWS compact serialization as input.
     *
     * @param compactSerialization the to be validated JWS compact serialization
     */
    public JWSValidator(JWSCompactSerialization compactSerialization) {
        super(compactSerialization.makeJWSStruct());
        this.signatureOctets = decode(compactSerialization.encodedSignature().getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * Validates the JSON web signature by using the given {@code Key}. In the event of assymetric algorithms (indicated by the JOSE header) this
     * MUST be a {@link java.security.PublicKey}  whereas symmetric algorithms require a {@link javax.crypto.SecretKey}.
     *
     * @param key the to used {@code Key}
     * @return indicates if the signature is valid
     * @throws GeneralSecurityException indicates that a problem occured during the signing process
     */
    public boolean validate(Key key) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("boolean", this, "validate(Key signingKey)");

        try {
            String encodedHeader = encode(this.jwsStruct.strJoseHeader());
            String encodedPayload = encode(this.jwsStruct.strPayload());
            this.jwa.init(key);
            String signingInput = String.format("%s.%s", encodedHeader, encodedPayload);
            byte[] signingInputOctets = signingInput.getBytes(StandardCharsets.US_ASCII);
            this.jwa.update(signingInputOctets);

            return this.jwa.verify(this.jwa.preValidating(this.signatureOctets));
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
