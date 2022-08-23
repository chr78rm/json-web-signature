package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
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
                    tracer.out().printfIndentln("xBytes = %s, xBytes.length = %d", JWSUtils.formatBytes(xBytes), xBytes.length);
                    tracer.out().printfIndentln("yBytes = %s, yBytes.length = %d", JWSUtils.formatBytes(yBytes), yBytes.length);
                    byte[] canonicalXBytes = JWSUtils.alignBytes(xBytes, FIELD_SIZE);
                    byte[] canonicalYBytes = JWSUtils.alignBytes(yBytes, FIELD_SIZE);
                    tracer.out().printfIndentln("canonicalXBytes = %s, canonicalXBytes.length = %d", JWSUtils.formatBytes(canonicalXBytes), canonicalXBytes.length);
                    tracer.out().printfIndentln("canonicalYBytes = %s, canonicalYBytes.length = %d", JWSUtils.formatBytes(canonicalYBytes), canonicalYBytes.length);
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
                    tracer.out().printfIndentln("dBytes = %s, dBytes.length = %d", JWSUtils.formatBytes(dBytes), dBytes.length);
                    byte[] canonicalDBytes = JWSUtils.alignBytes(dBytes, order.bitLength()/8);
                    tracer.out().printfIndentln("canonicalDBytes = %s, canonicalDBytes.length = %d", JWSUtils.formatBytes(canonicalDBytes), canonicalDBytes.length);
                    assertThat(canonicalDBytes.length == order.bitLength()/8).isTrue();
                } else {
                    throw new InvalidKeyException();
                }
            }
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithECKeyPair()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = "152384fd-1833-42ac-9bb6-8dafe7ede9f9";
            JsonWebKey jsonWebKey = JsonWebKey.of(keyPair)
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.toJson().getString("crv")).contains("NIST P-256");
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            assertThat(jsonWebKey.getPrivateKey()).isNotNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithECPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithECPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = "d1a52709-8266-4ee1-b1b5-bbbfcd4d69dd";
            JsonWebKey jsonWebKey = JsonWebKey.of(keyPair.getPublic())
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.toJson().getString("crv")).contains("NIST P-256");
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            assertThat(jsonWebKey.getPrivateKey()).isNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();
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
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("RSA");
            assertThat(jsonWebKey.getPrivateKey()).isNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithRSAKeyPair() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithRSAKeyPair()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = "4b6ba54f-dfb2-4b6f-98b0-b92afef88bd0";
            JsonWebKey jsonWebKey = JsonWebKey.of(keyPair)
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("RSA");
            assertThat(jsonWebKey.getPrivateKey()).isNotNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithSecretKey() throws NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithSecretKey()");

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            String kid = "be940bb6-f776-4999-a17d-d7251ef13b0b";
            JsonWebKey jsonWebKey = JsonWebKey.of(secretKey)
                    .withKid(kid)
                    .build();
            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.getAlgorithm()).isNotNull();
            assertThat(jsonWebKey.getAlgorithm()).isEqualTo("HS256");
            assertThat(jsonWebKey.getPublicKey()).isNull();
            assertThat(jsonWebKey.getPrivateKey()).isNull();
            assertThat(jsonWebKey.getSecretKey()).isNotNull();
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
