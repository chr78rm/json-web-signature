package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import de.christofreichardt.json.JsonTracer;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 *
 * @author Christof Reichardt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JWKUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JWKUnit.this.getCurrentTracer();
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
    void jwkSetUrl() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkSetUrl()");

        try {
            Path jwkSet_0 = Path.of(".", "keys", "jwk-set-0.json");
            assertThat(Files.exists(jwkSet_0)).isTrue();
            tracer.out().printfIndentln("jwkSet_0.toUri() = %s", jwkSet_0.normalize().toUri());
            assertThat(Files.exists(Path.of(jwkSet_0.normalize().toUri()))).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithECPubliKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithECPubliKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = "152384fd-1833-42ac-9bb6-8dafe7ede9f9";
            JsonWebKey jsonWebKey = JsonWebKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.toJson().getString("crv")).contains("NIST P-256");
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithRSAPublicKey() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithRSAPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = "bcc3ed94-5fac-4d07-9264-490d93b00036";
            JsonWebKey jsonWebKey = JsonWebKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
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
