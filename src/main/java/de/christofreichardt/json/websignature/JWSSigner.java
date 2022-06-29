package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.json.JsonObject;
import javax.json.JsonStructure;

/**
 *
 * @author Christof Reichardt
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
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
