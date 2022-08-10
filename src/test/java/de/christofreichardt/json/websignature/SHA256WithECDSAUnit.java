package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.json.Json;
import javax.json.JsonObject;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 *
 * @author Christof Reichardt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SHA256WithECDSAUnit implements Traceable, WithAssertions {

    @BeforeAll
    void init() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "init()");

        try {
        } finally {
            tracer.wayout();
        }
    }

    /**
     * The JSON Web Algorithm (JWA) 'ES256' specified in RFC 7518 requires the use of the NIST curve P-256. The test case prints the relevant curve parameter which can be checked against
     * the specification of the NIST. 
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">3.4. Digital Signature with ECDSA</a>
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">Digital Signature Standard (DSS)</a>
     * 
     * @throws GeneralSecurityException indicates problems when generating the key pair
     */
    @Test
    void withJsonObjects() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withJsonObjects()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
            tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
            tracer.out().printfIndentln("n = %s", ecParameterSpec.getOrder());
            tracer.out().printfIndentln("bitlength(%d) = %d", ecParameterSpec.getOrder(), ecParameterSpec.getOrder().bitLength());
            tracer.out().printfIndentln("cofactor = %d", ecParameterSpec.getCofactor());
            if (ecParameterSpec.getCurve().getField() instanceof ECFieldFp ecFieldFp) {
                tracer.out().printfIndentln("curve[a=%s, b=%s, p=%d]", 
                        ecParameterSpec.getCurve().getA().subtract(ecFieldFp.getP()), ecParameterSpec.getCurve().getB().toString(16), ecFieldFp.getP());
                tracer.out().printfIndentln("generator[x=%s, y=%s]", 
                        ecParameterSpec.getGenerator().getAffineX().toString(16), ecParameterSpec.getGenerator().getAffineY().toString(16));
            }

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();

            JsonObject fakePayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, fakePayload);
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.header(), jwsSigner.sign(keyPair.getPrivate()).payload(), compactSerialization.signature());
            jwsValidator = new JWSValidator(fakeSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    @AfterAll
    void exit() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "exit()");

        try {
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
