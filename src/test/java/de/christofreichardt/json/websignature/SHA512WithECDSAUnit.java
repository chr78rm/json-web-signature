package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SHA512WithECDSAUnit implements Traceable, WithAssertions {

    @BeforeAll
    void init() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "init()");

        try {
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withJsonObjects() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "dummy()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp521r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES512")
                    .build();
            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA512withECDSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA512withECDSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();

            JsonObject anotherPayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, anotherPayload);
            JWSCompactSerialization anotherCompactSerialization = jwsSigner.sign(ecPrivateKey);
            jwsValidator = new JWSValidator(anotherCompactSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
            JWSCompactSerialization fakedCompactSerialization = new JWSCompactSerialization(
                    compactSerialization.encodedHeader(), compactSerialization.encodedPayload(), anotherCompactSerialization.encodedSignature()
            );
            JWSCompactSerialization validCompactSerialization = new JWSCompactSerialization(
                    anotherCompactSerialization.encodedHeader(), anotherCompactSerialization.encodedPayload(), anotherCompactSerialization.encodedSignature()
            );
            jwsValidator = new JWSValidator(validCompactSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
            jwsValidator = new JWSValidator(fakedCompactSerialization);
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
