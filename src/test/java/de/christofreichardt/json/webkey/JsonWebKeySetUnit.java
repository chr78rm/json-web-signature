package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebKeySetUnit implements Traceable, WithAssertions {

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
            Path jwkSet_0 = Path.of(".", "json", "keys", "jwk-set-0.json");
            assertThat(Files.exists(jwkSet_0)).isTrue();
            tracer.out().printfIndentln("jwkSet_0.toUri() = %s", jwkSet_0.normalize().toUri());
            assertThat(Files.exists(Path.of(jwkSet_0.normalize().toUri()))).isTrue();
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
