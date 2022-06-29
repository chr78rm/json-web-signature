package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 *
 * @author Christof Reichardt
 */
public class JWSValidator extends JWSBase implements Traceable {

    final byte[] signatureOctets;
    
    public JWSValidator(JWSCompactSerialization compactSerialization) {
        super(compactSerialization.toJWSStruct());
        this.signatureOctets = decode(compactSerialization.signature().getBytes(StandardCharsets.ISO_8859_1));
    }
    
    public boolean validate(Key signingKey) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("boolean", this, "validate(Key signingKey)");

        try {
            String encodedHeader = encode(this.jwsStruct.strJoseHeader());
            String encodedPayload = encode(this.jwsStruct.strPayload());
            this.jwa.init(signingKey);
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
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
