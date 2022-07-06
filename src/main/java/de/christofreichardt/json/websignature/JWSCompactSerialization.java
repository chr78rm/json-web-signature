package de.christofreichardt.json.websignature;

import de.christofreichardt.json.websignature.JWSBase.JWSStruct;

/**
 *
 * @author Christof Reichardt
 */
public record JWSCompactSerialization(String header, String payload, String signature) {
    
    JWSStruct makeJWSStruct() {
        String strJoseHeader = JWSBase.decode(this.header);
        String strJWSPayload = JWSBase.decode(this.payload);
        
        return new JWSStruct(JWSBase.read(strJoseHeader).asJsonObject(), strJoseHeader, JWSBase.read(strJWSPayload), strJWSPayload);
    }

    @Override
    public String toString() {
        return String.format("%s.%s.%s", this.header, this.payload, this.signature);
    }
}
