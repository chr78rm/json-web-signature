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
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

/**
 * Low level class for the creating JSON web signatures. Subject to change. Do not use. The preferred entry point is the Fluent API.
 *
 * @author Christof Reichardt
 * @see de.christofreichardt.json.websignature.JWS
 */
public class JWSSigner extends JWSBase implements Traceable {

    public JWSSigner(JsonObject joseHeader, JsonStructure payload) {
        this(joseHeader, payload, JsonStructure::toString);
    }

    public JWSSigner(JsonObject joseHeader, JsonStructure payload, Json2StringConverter converter) {
        super(new JWSStruct(joseHeader, converter.convert(joseHeader), payload, converter.convert(payload)));
    }

    public JWSSigner(String strJoseHeader, String strPayload) {
        super(new JWSStruct(read(strJoseHeader).asJsonObject(), strJoseHeader, read(strPayload), strPayload));
    }

    public JWSCompactSerialization sign(Key signingKey) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("String", this, "sign(String strPayload, Key signingKey)");

        try {
            String encodedHeader = encode(this.jwsStruct.strJoseHeader());
            String encodedPayload = encode(this.jwsStruct.strPayload());
            this.jwa.init(signingKey);
            String signingInput = String.format("%s.%s", encodedHeader, encodedPayload);
            byte[] signingInputOctets = signingInput.getBytes(StandardCharsets.US_ASCII);
            this.jwa.update(signingInputOctets);
            byte[] signatureOctets = this.jwa.signature();
            String encodedSignature = encode(signatureOctets);

            return new JWSCompactSerialization(encodedHeader, encodedPayload, encodedSignature);
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
