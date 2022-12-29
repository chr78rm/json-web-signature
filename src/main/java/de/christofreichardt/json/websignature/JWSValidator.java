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
    
    public JWSValidator(JWSCompactSerialization compactSerialization) {
        super(compactSerialization.makeJWSStruct());
        this.signatureOctets = decode(compactSerialization.encodedSignature().getBytes(StandardCharsets.ISO_8859_1));
    }
    
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
            
            return this.jwa.verify(this.signatureOctets);
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
