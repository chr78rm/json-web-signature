package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.NoSuchAlgorithmException;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebSecretKeyUnit implements Traceable, WithAssertions {

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
    void withDefaults() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withDefaults()");

        try {
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of()
                    .build();
            tracer.out().printfIndentln("jsonWebSecretKey = %s", jsonWebSecretKey);
            assertThat(jsonWebSecretKey.secretKey).isNotNull();
            assertThat(jsonWebSecretKey.secretKey.getAlgorithm()).isEqualTo("HmacSHA256");
            assertThat(jsonWebSecretKey.algorithm).isEqualTo("HS256");
            assertThat(jsonWebSecretKey.keyType).isEqualTo("oct");
            assertThat(jsonWebSecretKey.kid).isNotNull();
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
