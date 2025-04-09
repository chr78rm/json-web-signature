package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import jakarta.json.*;
import jakarta.json.stream.JsonGenerator;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebKeyPairUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JsonWebKeyPairUnit.this.getCurrentTracer();
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
    void defaults() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "defaults()");

        try {
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebKeyPair.kid).isNull();
            assertThat(jsonWebKeyPair.getKeyPair().getPublic()).isEqualTo(jsonWebPublicKey.getPublicKey());
            assertThat(jsonWebKeyPair.getKid()).isEqualTo(jsonWebPublicKey.getKid());

            JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKey.fromJson(jsonWebKeyPair.toJson(), JsonWebKeyPair.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebKeyPair);
            this.jsonTracer.trace(recoveredJsonWebKeyPair.toJson());
            tracer.out().printfIndentln("jsonWebKeyPair.hashCode() = %d, recoveredJsonWebKeyPair.hashCode() = %d",
                    jsonWebKeyPair.hashCode(), recoveredJsonWebKeyPair.hashCode());

            assertThat(recoveredJsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(recoveredJsonWebKeyPair);
            assertThat(jsonWebKeyPair.hashCode()).isEqualTo(recoveredJsonWebKeyPair.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebKeyPair);

            assertThat(keys.contains(recoveredJsonWebKeyPair)).isTrue();
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
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withKid(kid)
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.kid).isEqualTo(kid);
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebKeyPair.getKeyPair().getPublic()).isEqualTo(jsonWebPublicKey.getPublicKey());
            assertThat(jsonWebKeyPair.getKid()).isEqualTo(jsonWebPublicKey.getKid());

            JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKey.fromJson(jsonWebKeyPair.toJson(), JsonWebKeyPair.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebKeyPair);
            this.jsonTracer.trace(recoveredJsonWebKeyPair.toJson());
            tracer.out().printfIndentln("jsonWebKeyPair.hashCode() = %d, recoveredJsonWebKeyPair.hashCode() = %d",
                    jsonWebKeyPair.hashCode(), recoveredJsonWebKeyPair.hashCode());

            assertThat(recoveredJsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(recoveredJsonWebKeyPair);
            assertThat(jsonWebKeyPair.hashCode()).isEqualTo(recoveredJsonWebKeyPair.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebKeyPair);

            assertThat(keys.contains(recoveredJsonWebKeyPair)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp521r1"})
    void withECGenParameterSpec(String curve) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECGenParameterSpec()");

        try {
            tracer.out().printfIndentln("curve = %s", curve);

            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve);
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(ecGenParameterSpec)
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebKeyPair.kid).isNull();
            assertThat(jsonWebKeyPair.getKeyPair().getPublic()).isEqualTo(jsonWebPublicKey.getPublicKey());
            assertThat(jsonWebKeyPair.getKid()).isEqualTo(jsonWebPublicKey.getKid());

            JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKey.fromJson(jsonWebKeyPair.toJson(), JsonWebKeyPair.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebKeyPair);
            this.jsonTracer.trace(recoveredJsonWebKeyPair.toJson());
            tracer.out().printfIndentln("jsonWebKeyPair.hashCode() = %d, recoveredJsonWebKeyPair.hashCode() = %d",
                    jsonWebKeyPair.hashCode(), recoveredJsonWebKeyPair.hashCode());

            assertThat(recoveredJsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(recoveredJsonWebKeyPair);
            assertThat(jsonWebKeyPair.hashCode()).isEqualTo(recoveredJsonWebKeyPair.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebKeyPair);

            assertThat(keys.contains(recoveredJsonWebKeyPair)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp521r1"})
    void withECKeyPairAndKid(String curve) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECKeyPairAndKid()");

        try {
            tracer.out().printfIndentln("curve = %s", curve);

            String kid = UUID.randomUUID().toString();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
                    .withKid(kid)
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebKeyPair.kid).isEqualTo(kid);
            assertThat(jsonWebKeyPair.getKeyPair().getPublic()).isEqualTo(jsonWebPublicKey.getPublicKey());
            assertThat(jsonWebKeyPair.getKid()).isEqualTo(jsonWebPublicKey.getKid());

            JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKey.fromJson(jsonWebKeyPair.toJson(), JsonWebKeyPair.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebKeyPair);
            this.jsonTracer.trace(recoveredJsonWebKeyPair.toJson());
            tracer.out().printfIndentln("jsonWebKeyPair.hashCode() = %d, recoveredJsonWebKeyPair.hashCode() = %d",
                    jsonWebKeyPair.hashCode(), recoveredJsonWebKeyPair.hashCode());

            assertThat(recoveredJsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(recoveredJsonWebKeyPair);
            assertThat(jsonWebKeyPair.hashCode()).isEqualTo(recoveredJsonWebKeyPair.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebKeyPair);

            assertThat(keys.contains(recoveredJsonWebKeyPair)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withRSAKeyGenParameterSpec() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withRSAKeyGenParameterSpec()");

        try {
            AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(algorithmParameterSpec)
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebKeyPair.keyType).isEqualTo("RSA");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(RSAPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(RSAPublicKey.class);
            assertThat(jsonWebKeyPair.kid).isNull();
            assertThat(jsonWebKeyPair.getKeyPair().getPublic()).isEqualTo(jsonWebPublicKey.getPublicKey());
            assertThat(jsonWebKeyPair.getKid()).isEqualTo(jsonWebPublicKey.getKid());

            JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKey.fromJson(jsonWebKeyPair.toJson(), JsonWebKeyPair.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebKeyPair);
            this.jsonTracer.trace(recoveredJsonWebKeyPair.toJson());
            tracer.out().printfIndentln("jsonWebKeyPair.hashCode() = %d, recoveredJsonWebKeyPair.hashCode() = %d",
                    jsonWebKeyPair.hashCode(), recoveredJsonWebKeyPair.hashCode());

            assertThat(recoveredJsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(jsonWebKeyPair);
            assertThat(jsonWebKeyPair).isEqualTo(recoveredJsonWebKeyPair);
            assertThat(jsonWebKeyPair.hashCode()).isEqualTo(recoveredJsonWebKeyPair.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebKeyPair);

            assertThat(keys.contains(recoveredJsonWebKeyPair)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void secp521r1() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "secp521r1()");

        try {
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp521r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            if (publicKey instanceof ECPublicKey ecPublicKey) {
                ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
                tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
                int fieldSize = ecParameterSpec.getCurve().getField().getFieldSize();
                tracer.out().printfIndentln("fieldSize = %d", fieldSize);
                tracer.out().printfIndentln("fieldSize(bits) = %d, fieldSize(bytes) = %d", fieldSize, (int) Math.ceil((double) fieldSize / 8));
                ECField ecField = ecPublicKey.getParams().getCurve().getField();
                if (ecField instanceof ECFieldFp ecFieldFp) {
                    tracer.out().printfIndentln("p = %d", ecFieldFp.getP());
                }
                tracer.out().printfIndentln("a = %d", ecPublicKey.getParams().getCurve().getA());
                tracer.out().printfIndentln("b = %d", ecPublicKey.getParams().getCurve().getB());
                tracer.out().printfIndentln("x = %d", ecPublicKey.getParams().getGenerator().getAffineX());
                tracer.out().printfIndentln("y = %d", ecPublicKey.getParams().getGenerator().getAffineY());
                tracer.out().printfIndentln("order = %d", ecPublicKey.getParams().getOrder());
            }
            PrivateKey privateKey = keyPair.getPrivate();
            if (privateKey instanceof ECPrivateKey ecPrivateKey) {
                ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
                tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
                int fieldSize = ecParameterSpec.getCurve().getField().getFieldSize();
                tracer.out().printfIndentln("fieldSize = %d", fieldSize);
                tracer.out().printfIndentln("fieldSize(bits) = %d, fieldSize(bytes) = %d", fieldSize, (int) Math.ceil((double) fieldSize / 8));
                BigInteger order = ecParameterSpec.getOrder();
                tracer.out().printfIndentln("order.bitLength() = %d, bytesLen(order) = %d, order = %d", order.bitLength(), (int) Math.ceil((double) order.bitLength() / 8), order);
            }
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void secp256r1() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "secp256r1()");

        try {
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            if (publicKey instanceof ECPublicKey ecPublicKey) {
                ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
                tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
                int fieldSize = ecParameterSpec.getCurve().getField().getFieldSize();
                tracer.out().printfIndentln("fieldSize(bits) = %d, fieldSize(bytes) = %d", fieldSize, (int) Math.ceil((double) fieldSize / 8));
            }
            PrivateKey privateKey = keyPair.getPrivate();
            if (privateKey instanceof ECPrivateKey ecPrivateKey) {
                ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
                tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
                int fieldSize = ecParameterSpec.getCurve().getField().getFieldSize();
                tracer.out().printfIndentln("fieldSize = %d", fieldSize);
                tracer.out().printfIndentln("fieldSize(bits) = %d, fieldSize(bytes) = %d", fieldSize, (int) Math.ceil((double) fieldSize / 8));
                BigInteger order = ecParameterSpec.getOrder();
                tracer.out().printfIndentln("order.bitLength() = %d, bytesLen(order) = %d, order = %d", order.bitLength(), (int) Math.ceil((double) order.bitLength() / 8), order);
            }

            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(ecGenParameterSpec)
                    .build();
            JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();

            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jsonWebPublicKey.toJson());
        } finally {
            tracer.wayout();
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class Examples {

        @Test
        void defaults() throws GeneralSecurityException, IOException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "defaults()");

            try {
                JsonWebKeyPair jsonWebKeyPair;
                Path path = Path.of("json", "examples", "my-first-jsonwebkeypair.json");
                {
                    jsonWebKeyPair = JsonWebKeyPair.of()
                            .build();
                    JsonObject jsonObject = jsonWebKeyPair.toJson();
                    JsonWebKeyPairUnit.this.jsonTracer.trace(jsonObject);
                    JsonWriterFactory jsonWriterFactory = Json.createWriterFactory(Map.of(JsonGenerator.PRETTY_PRINTING, Boolean.TRUE));
                    try (FileOutputStream fileOutputStream = new FileOutputStream(path.toFile());
                         JsonWriter jsonWriter = jsonWriterFactory.createWriter(fileOutputStream)) {
                        jsonWriter.write(jsonWebKeyPair.toJson());
                    }
                }

                {
                    JsonWebPublicKey jsonWebPublicKey = jsonWebKeyPair.jsonWebPublicKey();
                    JsonObject jsonObject = jsonWebPublicKey.toJson();
                    JsonWebKeyPairUnit.this.jsonTracer.trace(jsonObject);
                }

                {
                    JsonObject jsonObject;
                    try (FileInputStream fileInputStream = new FileInputStream(path.toFile());
                         JsonReader jsonReader = Json.createReader(fileInputStream)) {
                        jsonObject = jsonReader.readObject();
                    }
                    JsonWebKeyPair recoveredJsonWebKeyPair = JsonWebKeyPair.fromJson(jsonObject);
                    assert recoveredJsonWebKeyPair.equals(jsonWebKeyPair);
                }

                {
                    JsonObject jsonObject;
                    try (FileInputStream fileInputStream = new FileInputStream(path.toFile());
                         JsonReader jsonReader = Json.createReader(fileInputStream)) {
                        jsonObject = jsonReader.readObject();
                    }
                    JsonWebPublicKey recoveredJsonWebPublicKey = JsonWebPublicKey.fromJson(jsonObject);
                    assert recoveredJsonWebPublicKey.equals(jsonWebKeyPair.jsonWebPublicKey());
                }
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
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .withKid(kid)
                        .build();

                JsonWebKeyPairUnit.this.jsonTracer.trace(jsonWebKeyPair.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void withECGenParameterSpec() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "withECGenParameterSpec()");

            try {
                AlgorithmParameterSpec algorithmParameterSpec = new ECGenParameterSpec("secp521r1");
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(algorithmParameterSpec)
                        .build();

                JsonWebKeyPairUnit.this.jsonTracer.trace(jsonWebKeyPair.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void withKeyPair() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "withKeyPair()");

            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
                keyPairGenerator.initialize(ecGenParameterSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                String kid = UUID.randomUUID().toString();
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
                        .withKid(kid)
                        .build();

                JsonWebKeyPairUnit.this.jsonTracer.trace(jsonWebKeyPair.toJson());
            } finally {
                tracer.wayout();
            }
        }

        @Test
        void withRSAKeyGenParameterSpec() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "withRSAKeyGenParameterSpec()");

            try {
                AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(algorithmParameterSpec)
                        .build();

                JsonWebKeyPairUnit.this.jsonTracer.trace(jsonWebKeyPair.toJson());
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
