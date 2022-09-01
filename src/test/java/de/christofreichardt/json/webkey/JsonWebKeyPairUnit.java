package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.GeneralSecurityException;
import java.security.spec.ECParameterSpec;
import java.util.UUID;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebKeyPairUnit implements Traceable, WithAssertions {

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
    void defaults() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "defaults()");

        try {
            JsonWebKey jsonWebKey = JsonWebKey.of(JsonWebKeyPair.class)
                    .build();
            if (!(jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair)) {
                throw new RuntimeException();
            }
            tracer.out().printfIndentln("jsonWebKey = %s", jsonWebKey);
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void defaultsWithKid() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "defaultsWithKid()");

        try {
            String kid = UUID.randomUUID().toString();
            JsonWebKey jsonWebKey = JsonWebKey.of(JsonWebKeyPair.class)
                    .withKid(kid)
                    .build();
            if (!(jsonWebKey instanceof JsonWebKeyPair jsonWebKeyPair)) {
                throw new RuntimeException();
            }
            tracer.out().printfIndentln("jsonWebKey = %s", jsonWebKey);
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.kid).isEqualTo(kid);
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
