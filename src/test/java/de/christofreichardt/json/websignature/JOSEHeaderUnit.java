package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

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

    record Algo (String parameterSpecName, String alg) {}

    static Algo[] algos() {
        return new Algo[]{new Algo("secp256r1", "ES256"), new Algo("secp521r1", "ES512")};
    }

    @ParameterizedTest
    @MethodSource("algos")
    void withECPublicKey(Algo algo) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECPublicKey()");

        try {
            tracer.out().printfIndentln("algo = %s", algo);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(algo.parameterSpecName());
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = UUID.randomUUID().toString(), typ = "JWT";
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            JOSEHeader joseHeader = JOSEHeader.of(jsonWebPublicKey)
                    .withTyp(typ)
                    .build();
            JsonObject joseHeaderView = joseHeader.toJson();

            this.jsonTracer.trace(joseHeaderView);
            assertThat(joseHeaderView.getString("kid")).isEqualTo(kid);
            assertThat(joseHeaderView.getString("typ")).isEqualTo(typ);
            assertThat(joseHeaderView.getString("alg")).isEqualTo(algo.alg());

            JOSEHeader recoveredJoseHeader = JOSEHeader.fromJson(joseHeaderView);
            this.jsonTracer.trace(recoveredJoseHeader.toJson());
            assertThat(recoveredJoseHeader).isEqualTo(joseHeader);

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();
            JWSSigner jwsSigner = new JWSSigner(joseHeaderView, payload);
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.validate(joseHeader.getJsonWebPublicKey().getPublicKey())).isTrue();
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
            String kid = UUID.randomUUID().toString(), typ = "JWT", alg = "RS256";
            tracer.out().printfIndentln("keyPair.getPublic().getAlgorithm() = %s", keyPair.getPublic().getAlgorithm());
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            JOSEHeader joseHeader = JOSEHeader.of(jsonWebPublicKey)
                    .withTyp(typ)
                    .build();
            JsonObject joseHeaderView = joseHeader.toJson();

            this.jsonTracer.trace(joseHeaderView);
            assertThat(joseHeaderView.getString("kid")).isEqualTo(kid);
            assertThat(joseHeaderView.getString("typ")).isEqualTo(typ);
            assertThat(joseHeaderView.getString("alg")).isEqualTo(alg);

            JOSEHeader recoveredJoseHeader = JOSEHeader.fromJson(joseHeaderView);
            this.jsonTracer.trace(recoveredJoseHeader.toJson());
            assertThat(recoveredJoseHeader).isEqualTo(joseHeader);

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();
            JWSSigner jwsSigner = new JWSSigner(joseHeaderView, payload);
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.validate(joseHeader.getJsonWebPublicKey().getPublicKey())).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withoutPublicKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "exit()");

        try {
            String kid = UUID.randomUUID().toString(), typ = "JWT", alg = "RS256";
            JOSEHeader joseHeader = JOSEHeader.of(alg)
                    .withKid(kid)
                    .withTyp(typ)
                    .build();
            JsonObject joseHeaderView = joseHeader.toJson();

            this.jsonTracer.trace(joseHeader.toJson());
            assertThat(joseHeaderView.getString("kid")).isEqualTo(kid);
            assertThat(joseHeaderView.getString("typ")).isEqualTo(typ);
            assertThat(joseHeaderView.getString("alg")).isEqualTo(alg);

            JOSEHeader recoveredJoseHeader = JOSEHeader.fromJson(joseHeaderView);
            this.jsonTracer.trace(recoveredJoseHeader.toJson());
            assertThat(recoveredJoseHeader).isEqualTo(joseHeader);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ambigousKids_1() throws FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ambigousKids_1()");

        try {
            JsonObject joseHeader;
            File joseHeaderFile = Path.of("json", "jose-headers", "ambigous-kids.json").toFile();
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(joseHeaderFile))) {
                joseHeader = jsonReader.readObject();
            }
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> JOSEHeader.fromJson(joseHeader));
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void inappropriatePublicKey() throws FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "inappropriatePublicKey()");

        try {
            JsonObject joseHeader;
            File joseHeaderFile = Path.of("json", "jose-headers", "inappropriate-public-key.json").toFile();
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(joseHeaderFile))) {
                joseHeader = jsonReader.readObject();
            }
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> JOSEHeader.fromJson(joseHeader));
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void inappropriateCurve() throws GeneralSecurityException, FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "inappropriateCurve()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp384r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(UUID.randomUUID().toString())
                    .build();
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            JsonObject joseHeader;
            File joseHeaderFile = Path.of("json", "jose-headers", "inappropriate-curve.json").toFile();
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(joseHeaderFile))) {
                joseHeader = jsonReader.readObject();
            }
            assertThatExceptionOfType(UnsupportedOperationException.class)  // todo: this should really be an IllegalArgumentException (?)
                    .isThrownBy(() -> JOSEHeader.fromJson(joseHeader));
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void unsupportedAlgorithm() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "unsupportedAlgorithm()");

        try {
            String kid = UUID.randomUUID().toString(), typ = "JWT", alg = "PS384";
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> JOSEHeader.of(alg)
                            .withKid(kid)
                            .withTyp(typ)
                            .build());
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ambigousKids_2() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ambigousKids_2()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = UUID.randomUUID().toString(), typ = "JWT";
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(
                            () -> JOSEHeader.of(jsonWebPublicKey)
                            .withTyp(typ)
                            .withKid(UUID.randomUUID().toString())
                            .build()
                    )
                    .withMessage("Ambigous kids.");

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(
                            () -> JOSEHeader.of(jsonWebPublicKey)
                                    .withTyp(typ)
                                    .withKid(null)
                                    .build()
                    )
                    .withMessage("Ambigous kids.");

            JOSEHeader joseHeader = JOSEHeader.of(jsonWebPublicKey)
                    .withTyp(typ)
                    .withKid(kid)
                    .build();

            this.jsonTracer.trace(joseHeader.toJson());
        } finally {
            tracer.wayout();
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class Examples {

        @Test
        void defaults() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "defaults()");

            try {
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .build();
                JOSEHeader joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .build();
                JOSEHeaderUnit.this.jsonTracer.trace(joseHeader.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void defaultsWithKid_1() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "defaultsWithKid_1()");

            try {
                String kid = UUID.randomUUID().toString();
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .withKid(kid)
                        .build();
                JOSEHeader joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .build();
                JOSEHeaderUnit.this.jsonTracer.trace(joseHeader.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void defaultsWithKid_2() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "defaultsWithKid_2()");

            try {
                String kid = UUID.randomUUID().toString();
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .build();
                JOSEHeader joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .withKid(kid)
                        .build();
                JOSEHeaderUnit.this.jsonTracer.trace(joseHeader.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void ambigousKids() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "ambigousKids()");

            try {
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .withKid(UUID.randomUUID().toString())
                        .build();
                assertThatExceptionOfType(IllegalArgumentException.class)
                        .isThrownBy(
                                () -> JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                                        .withKid(UUID.randomUUID().toString())
                                        .build()
                        );
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void withKidAndTyp() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "withKidAndTyp()");

            try {
                String kid = UUID.randomUUID().toString();
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .build();
                JOSEHeader joseHeader = JOSEHeader.of(jsonWebKeyPair.jsonWebPublicKey())
                        .withKid(kid)
                        .withTyp("JOSE")
                        .build();
                JOSEHeaderUnit.this.jsonTracer.trace(joseHeader.toJson());
            } finally {
                tracer.wayout();
            }
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
