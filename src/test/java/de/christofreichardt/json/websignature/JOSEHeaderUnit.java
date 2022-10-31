package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import javax.json.Json;
import javax.json.JsonObject;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JOSEHeaderUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JOSEHeaderUnit.this.getCurrentTracer();
        }
    }

    final MyJsonTracer jsonTracer = new MyJsonTracer();

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
    void withECPublicKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = UUID.randomUUID().toString();
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            JOSEHeader joseHeader = JOSEHeader.of("ES256")
                    .withKid(kid)
                    .withJsonWebPublicKey(jsonWebPublicKey)
                    .withTyp("JWT")
                    .build();
            this.jsonTracer.trace(joseHeader.toJson());

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();
            JWSSigner jwsSigner = new JWSSigner(joseHeader.toJson(), payload);
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withRSAPublicKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withRSAPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = UUID.randomUUID().toString();
            tracer.out().printfIndentln("keyPair.getPublic().getAlgorithm() = %s", keyPair.getPublic().getAlgorithm());
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            JOSEHeader joseHeader = JOSEHeader.of("RS256")
                    .withKid(kid)
                    .withJsonWebPublicKey(jsonWebPublicKey)
                    .withTyp("JWT")
                    .build();
            this.jsonTracer.trace(joseHeader.toJson());

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();
            JWSSigner jwsSigner = new JWSSigner(joseHeader.toJson(), payload);
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
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
