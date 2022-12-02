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

import de.christofreichardt.json.websignature.JWSBase.JWSStruct;

/**
 * A holder for the strings representing the compact serialization format as specified by RFC 7515 (JSON Web Signature).
 *
 * @author Christof Reichardt
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1">Section 3.1 of RFC 7515</a>
 */
public record JWSCompactSerialization(String header, String payload, String signature) {

    /**
     * Factory method which expects an actual compact serialization format.
     *
     * @param compactSerialization an actual compact serialization format.
     * @return a JWSCompactSerialization instance.
     */
    public static JWSCompactSerialization of(String compactSerialization) {
        String[] splits = compactSerialization.split("\\.");
        if (splits.length != 3) {
            throw new IllegalArgumentException("Not a compact serialization.");
        }
        return new JWSCompactSerialization(splits[0], splits[1], splits[2]);
    }
    
    JWSStruct makeJWSStruct() {
        String strJoseHeader = JWSBase.decode(this.header);
        String strJWSPayload = JWSBase.decode(this.payload);
        
        return new JWSStruct(JWSBase.read(strJoseHeader).asJsonObject(), strJoseHeader, JWSBase.read(strJWSPayload), strJWSPayload);
    }

    /**
     * Returns the actual compact serialization format as string object.
     *
     * @return the actual compact serialization format as string object.
     */
    @Override
    public String toString() {
        return String.format("%s.%s.%s", this.header, this.payload, this.signature);
    }
}
