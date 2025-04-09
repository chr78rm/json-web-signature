package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.JsonUtils;
import jakarta.json.JsonString;
import java.io.FileInputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebPublicKeyUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JsonWebPublicKeyUnit.this.getCurrentTracer();
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
    void bigIntegerArithmetic() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "bigIntegerArithmetic()");

        try {
            final int TRIALS = 100;
            for (int i = 0; i < TRIALS; i++) {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
                keyPairGenerator.initialize(ecGenParameterSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                if (keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
                    final int FIELD_SIZE = 32; // bytes
                    tracer.out().printfIndentln("fieldSize = %d", ecPublicKey.getParams().getCurve().getField().getFieldSize());
                    assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize() / 8 == FIELD_SIZE).isTrue();
                    byte[] xBytes = ecPublicKey.getW().getAffineX().toByteArray();
                    byte[] yBytes = ecPublicKey.getW().getAffineY().toByteArray();
                    tracer.out().printfIndentln("xBytes = %s, xBytes.length = %d", JsonWebKeyUtils.formatBytes(xBytes), xBytes.length);
                    tracer.out().printfIndentln("yBytes = %s, yBytes.length = %d", JsonWebKeyUtils.formatBytes(yBytes), yBytes.length);
                    byte[] canonicalXBytes = JsonWebKeyUtils.alignBytes(xBytes, FIELD_SIZE);
                    byte[] canonicalYBytes = JsonWebKeyUtils.alignBytes(yBytes, FIELD_SIZE);
                    tracer.out().printfIndentln("canonicalXBytes = %s, canonicalXBytes.length = %d", JsonWebKeyUtils.formatBytes(canonicalXBytes), canonicalXBytes.length);
                    tracer.out().printfIndentln("canonicalYBytes = %s, canonicalYBytes.length = %d", JsonWebKeyUtils.formatBytes(canonicalYBytes), canonicalYBytes.length);
                    assertThat(new BigInteger(1, canonicalXBytes)).isEqualByComparingTo(ecPublicKey.getW().getAffineX());
                    assertThat(new BigInteger(1, canonicalYBytes)).isEqualByComparingTo(ecPublicKey.getW().getAffineY());
                    assertThat(canonicalXBytes.length == FIELD_SIZE).isTrue();
                    assertThat(canonicalYBytes.length == FIELD_SIZE).isTrue();
                } else {
                    throw new InvalidKeyException();
                }
                if (keyPair.getPrivate() instanceof ECPrivateKey ecPrivateKey) {
                    BigInteger order = ecPrivateKey.getParams().getOrder();
                    BigInteger d = ecPrivateKey.getS();
                    byte[] dBytes = d.toByteArray();
                    tracer.out().printfIndentln("order = %1$d, #bytes(order) = %2$d", order, order.bitLength()/8);
                    tracer.out().printfIndentln("dBytes = %s, dBytes.length = %d", JsonWebKeyUtils.formatBytes(dBytes), dBytes.length);
                    byte[] canonicalDBytes = JsonWebKeyUtils.alignBytes(dBytes, order.bitLength()/8);
                    tracer.out().printfIndentln("canonicalDBytes = %s, canonicalDBytes.length = %d", JsonWebKeyUtils.formatBytes(canonicalDBytes), canonicalDBytes.length);
                    assertThat(canonicalDBytes.length == order.bitLength()/8).isTrue();
                } else {
                    throw new InvalidKeyException();
                }
            }
        } finally {
            tracer.wayout();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp521r1"})
    void withECPublicKey(String curve) throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECPublicKey(String curve)");

        try {
            tracer.out().printfIndentln("curve = %s", curve);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(publicKey)
                    .build();

            tracer.out().printfIndentln("jsonWebPublicKey = %s", jsonWebPublicKey);
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebPublicKey.keyType).isEqualTo("EC");
            assertThat(jsonWebPublicKey.algorithmParameterSpec).isInstanceOf(ECParameterSpec.class);
            assertThat(jsonWebPublicKey.publicKey).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebPublicKey.kid).isNull();

            JsonWebPublicKey recoveredJsonWebPublicKey = JsonWebKey.fromJson(jsonWebPublicKey.toJson(), JsonWebPublicKey.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebPublicKey);
            this.jsonTracer.trace(recoveredJsonWebPublicKey.toJson());
            tracer.out().printfIndentln("jsonWebPublicKey.hashCode() = %d, recoveredJsonWebPublicKey.hashCode() = %d",
                    jsonWebPublicKey.hashCode(), recoveredJsonWebPublicKey.hashCode());

            assertThat(recoveredJsonWebPublicKey.equals(jsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.equals(jsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.equals(recoveredJsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.hashCode()).isEqualTo(recoveredJsonWebPublicKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebPublicKey);

            assertThat(keys.contains(recoveredJsonWebPublicKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void keycloakECCerts() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "keycloakECCerts()");

        try {
            String key = """
                  {
                      "kid": "Rf1c0xrE03Ud68kawPN_ZGcZ9GUNm1Au1gI0ieqxC44",
                      "kty": "EC",
                      "alg": "ES256",
                      "use": "sig",
                      "crv": "P-256",
                      "x": "RVIMLIqI9KwvB1vxAlCdqGlot3IZJqR8F3f83zSWZag",
                      "y": "UADjV5Nuvctq0DilRw_TyeoByNL1h6LKTR0Bi3y3Vbk"
                  }
                  """;
            JsonObject keyView;
            try (StringReader stringReader = new StringReader(key);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                keyView = jsonReader.readObject();
            }
            this.jsonTracer.trace(keyView);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(keyView);
            this.jsonTracer.trace(jsonWebPublicKey.toJson());
            assertThat(jsonWebPublicKey.getKeyType()).isEqualTo("EC");
            assertThat(jsonWebPublicKey.getKid()).isEqualTo("Rf1c0xrE03Ud68kawPN_ZGcZ9GUNm1Au1gI0ieqxC44");
            assertThat(JsonUtils.orElseThrow(jsonWebPublicKey.toJson(), "crv", JsonString.class).getString()).isIn("P-256", "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)");
            assertThat(JsonUtils.orElseThrow(jsonWebPublicKey.toJson(), "x", JsonString.class).getString()).isEqualTo("RVIMLIqI9KwvB1vxAlCdqGlot3IZJqR8F3f83zSWZag");
            assertThat(JsonUtils.orElseThrow(jsonWebPublicKey.toJson(), "y", JsonString.class).getString()).isEqualTo("UADjV5Nuvctq0DilRw_TyeoByNL1h6LKTR0Bi3y3Vbk");
            assertThat(JsonUtils.orElseThrow(jsonWebPublicKey.toJson(), "kid", JsonString.class).getString()).isEqualTo("Rf1c0xrE03Ud68kawPN_ZGcZ9GUNm1Au1gI0ieqxC44");
            assertThat(JsonUtils.orElseThrow(jsonWebPublicKey.toJson(), "kty", JsonString.class).getString()).isEqualTo("EC");
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKidAndRSAPublicKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withKidAndRSAPublicKey()");

        try {
            String kid = UUID.randomUUID().toString();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
            keyPairGenerator.initialize(algorithmParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();

            tracer.out().printfIndentln("jsonWebPublicKey = %s", jsonWebPublicKey);
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            assertThat(jsonWebPublicKey.keyType).isEqualTo("RSA");
            assertThat(jsonWebPublicKey.algorithmParameterSpec).isNull();
            assertThat(jsonWebPublicKey.publicKey).isInstanceOf(RSAPublicKey.class);
            assertThat(jsonWebPublicKey.kid).isEqualTo(kid);

            JsonWebPublicKey recoveredJsonWebPublicKey = JsonWebKey.fromJson(jsonWebPublicKey.toJson(), JsonWebPublicKey.class);

            tracer.out().printfIndentln("recoveredJsonWebPublicKey = %s", recoveredJsonWebPublicKey);
            this.jsonTracer.trace(recoveredJsonWebPublicKey.toJson());
            tracer.out().printfIndentln("jsonWebPublicKey.hashCode() = %d, recoveredJsonWebPublicKey.hashCode() = %d",
                    jsonWebPublicKey.hashCode(), recoveredJsonWebPublicKey.hashCode());

            assertThat(recoveredJsonWebPublicKey.equals(jsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.equals(jsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.equals(recoveredJsonWebPublicKey)).isTrue();
            assertThat(jsonWebPublicKey.hashCode()).isEqualTo(recoveredJsonWebPublicKey.hashCode());

            Set<JsonWebKey> keys = new HashSet<>();
            keys.add(jsonWebPublicKey);

            assertThat(keys.contains(recoveredJsonWebPublicKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void missingCrvParameter() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "missingCrvParameter()");

        try {
            final Path keyFile = Path.of("json", "keys", "missing-crv-param.json");
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> {
                        JsonObject jsonObject;
                        try (JsonReader jsonReader = Json.createReader(new FileInputStream(keyFile.toFile()))) {
                            jsonObject = jsonReader.readObject();
                        }
                        JsonWebKey.fromJson(jsonObject, JsonWebPublicKey.class);
                    });
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
