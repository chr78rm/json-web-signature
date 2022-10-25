package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebSecretKeyUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JsonWebSecretKeyUnit.this.getCurrentTracer();
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
    void withDefaults() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withDefaults()");

        try {
            final int DEFAULT_KEY_SIZE = 256; // Bits
            final String DEFAULT_ALGORITHM = "HmacSHA256";
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of()
                    .build();

            tracer.out().printfIndentln("jsonWebSecretKey = %s", jsonWebSecretKey);
            this.jsonTracer.trace(jsonWebSecretKey.toJson());

            assertThat(jsonWebSecretKey.secretKey).isNotNull();
            assertThat(jsonWebSecretKey.secretKey.getAlgorithm()).isEqualTo(DEFAULT_ALGORITHM);
            assertThat(jsonWebSecretKey.secretKey.getEncoded().length).isEqualTo(DEFAULT_KEY_SIZE / 8);
            assertThat(jsonWebSecretKey.algorithm).isEqualTo(JsonWebSecretKey.JDK2JSON_ALGO_MAP.get(DEFAULT_ALGORITHM));
            assertThat(jsonWebSecretKey.keyType).isEqualTo("oct");
            assertThat(jsonWebSecretKey.kid).isNull();

            JsonWebSecretKey recoveredJsonWebSecretKey = JsonWebKey.fromJson(jsonWebSecretKey.toJson(), JsonWebSecretKey.class);

            tracer.out().printfIndentln("recoveredJsonWebSecretKey = %s", recoveredJsonWebSecretKey);
            this.jsonTracer.trace(recoveredJsonWebSecretKey.toJson());
            tracer.out().printfIndentln("jsonWebSecretKey.hashCode() = %d, recoveredJsonWebSecretKey.hashCode() = %d",
                    jsonWebSecretKey.hashCode(), recoveredJsonWebSecretKey.hashCode());

            assertThat(recoveredJsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(recoveredJsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.hashCode()).isEqualTo(jsonWebSecretKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebSecretKey);

            assertThat(keys.contains(recoveredJsonWebSecretKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKeysizeAndAlgorithm() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withKeysizeAndAlgorithm()");

        try {
            final int KEY_SIZE = 2048;
            final String ALGORITHM = "HmacSHA512";
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of()
                    .withAlgorithm(ALGORITHM)
                    .withKeysize(KEY_SIZE)
                    .build();

            tracer.out().printfIndentln("jsonWebSecretKey = %s", jsonWebSecretKey);
            this.jsonTracer.trace(jsonWebSecretKey.toJson());

            assertThat(jsonWebSecretKey.secretKey).isNotNull();
            assertThat(jsonWebSecretKey.secretKey.getAlgorithm()).isEqualTo(ALGORITHM);
            assertThat(jsonWebSecretKey.algorithm).isEqualTo(JsonWebSecretKey.JDK2JSON_ALGO_MAP.get(ALGORITHM));
            assertThat(jsonWebSecretKey.secretKey.getEncoded().length).isEqualTo(KEY_SIZE / 8);
            assertThat(jsonWebSecretKey.keyType).isEqualTo("oct");
            assertThat(jsonWebSecretKey.kid).isNull();

            JsonWebSecretKey recoveredJsonWebSecretKey = JsonWebKey.fromJson(jsonWebSecretKey.toJson(), JsonWebSecretKey.class);

            tracer.out().printfIndentln("recoveredJsonWebSecretKey = %s", recoveredJsonWebSecretKey);
            this.jsonTracer.trace(recoveredJsonWebSecretKey.toJson());
            tracer.out().printfIndentln("jsonWebSecretKey.hashCode() = %d, recoveredJsonWebSecretKey.hashCode() = %d",
                    jsonWebSecretKey.hashCode(), recoveredJsonWebSecretKey.hashCode());

            assertThat(recoveredJsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(recoveredJsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.hashCode()).isEqualTo(jsonWebSecretKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebSecretKey);

            assertThat(keys.contains(recoveredJsonWebSecretKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKid() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withKid()");

        try {
            String kid = UUID.randomUUID().toString();
            final int DEFAULT_KEY_SIZE = 256; // Bits
            final String DEFAULT_ALGORITHM = "HmacSHA256";
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of()
                    .withKid(kid)
                    .build();

            tracer.out().printfIndentln("jsonWebSecretKey = %s", jsonWebSecretKey);
            this.jsonTracer.trace(jsonWebSecretKey.toJson());

            assertThat(jsonWebSecretKey.secretKey).isNotNull();
            assertThat(jsonWebSecretKey.secretKey.getAlgorithm()).isEqualTo(DEFAULT_ALGORITHM);
            assertThat(jsonWebSecretKey.secretKey.getEncoded().length).isEqualTo(DEFAULT_KEY_SIZE / 8);
            assertThat(jsonWebSecretKey.algorithm).isEqualTo(JsonWebSecretKey.JDK2JSON_ALGO_MAP.get(DEFAULT_ALGORITHM));
            assertThat(jsonWebSecretKey.keyType).isEqualTo("oct");
            assertThat(jsonWebSecretKey.kid).isEqualTo(kid);

            JsonWebSecretKey recoveredJsonWebSecretKey = JsonWebKey.fromJson(jsonWebSecretKey.toJson(), JsonWebSecretKey.class);

            tracer.out().printfIndentln("recoveredJsonWebSecretKey = %s", recoveredJsonWebSecretKey);
            this.jsonTracer.trace(recoveredJsonWebSecretKey.toJson());
            tracer.out().printfIndentln("jsonWebSecretKey.hashCode() = %d, recoveredJsonWebSecretKey.hashCode() = %d",
                    jsonWebSecretKey.hashCode(), recoveredJsonWebSecretKey.hashCode());

            assertThat(recoveredJsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(recoveredJsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.hashCode()).isEqualTo(jsonWebSecretKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebSecretKey);

            assertThat(keys.contains(recoveredJsonWebSecretKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKidAndSecretKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withKidAndSecretKey()");

        try {
            String kid = UUID.randomUUID().toString();
            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of()
                    .withKid(kid)
                    .withSecretKey(secretKey)
                    .build();

            tracer.out().printfIndentln("jsonWebSecretKey = %s", jsonWebSecretKey);
            this.jsonTracer.trace(jsonWebSecretKey.toJson());

            assertThat(jsonWebSecretKey.secretKey).isNotNull();
            assertThat(jsonWebSecretKey.secretKey.getAlgorithm()).isEqualTo(ALGORITHM);
            assertThat(jsonWebSecretKey.algorithm).isEqualTo(JsonWebSecretKey.JDK2JSON_ALGO_MAP.get(ALGORITHM));
            assertThat(jsonWebSecretKey.secretKey.getEncoded().length).isEqualTo(KEY_SIZE / 8);
            assertThat(jsonWebSecretKey.keyType).isEqualTo("oct");
            assertThat(jsonWebSecretKey.kid).isEqualTo(kid);

            JsonWebSecretKey recoveredJsonWebSecretKey = JsonWebKey.fromJson(jsonWebSecretKey.toJson(), JsonWebSecretKey.class);

            tracer.out().printfIndentln("recoveredJsonWebSecretKey = %s", recoveredJsonWebSecretKey);
            this.jsonTracer.trace(recoveredJsonWebSecretKey.toJson());
            tracer.out().printfIndentln("jsonWebSecretKey.hashCode() = %d, recoveredJsonWebSecretKey.hashCode() = %d",
                    jsonWebSecretKey.hashCode(), recoveredJsonWebSecretKey.hashCode());

            assertThat(recoveredJsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(jsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.equals(recoveredJsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey.hashCode()).isEqualTo(jsonWebSecretKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebSecretKey);
            JsonWebSecretKey anotherJsonWebSecretKey = JsonWebSecretKey.of()
                    .withKid(UUID.randomUUID().toString())
                    .withSecretKey(secretKey)
                    .build();
            keys.add(anotherJsonWebSecretKey);

            assertThat(keys.contains(recoveredJsonWebSecretKey)).isTrue();
            assertThat(keys.contains(anotherJsonWebSecretKey)).isTrue();
            assertThat(jsonWebSecretKey).isNotEqualTo(anotherJsonWebSecretKey);
            assertThat(keys.size()).isEqualTo(2);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKeysizeAfterSecretKey() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withKeysizeAfterSecretKey()");

        try {
            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> JsonWebSecretKey.of()
                            .withSecretKey(secretKey)
                            .withKeysize(KEY_SIZE * 2)
                            .build()
                    );
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withAlgorithmAfterSecretKey() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withAlgorithmAfterSecretKey()");

        try {
            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> JsonWebSecretKey.of()
                            .withSecretKey(secretKey)
                            .withAlgorithm("HmacSHA512")
                            .build()
                    );
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
