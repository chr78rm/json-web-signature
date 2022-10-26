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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
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
    void jwkWithECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
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

            if (keyPair.getPublic() instanceof ECPublicKey ecGenPublicKey) {
                tracer.out().printfIndentln("x = %d", ecGenPublicKey.getW().getAffineX());
                tracer.out().printfIndentln("y = %d", ecGenPublicKey.getW().getAffineY());
            } else {
                throw new RuntimeException();
            }
            if (keyPair.getPrivate() instanceof ECPrivateKey ecGenPrivateKey) {
                tracer.out().printfIndentln("ecGenPrivateKey.getS() = %d", ecGenPrivateKey.getS());
            } else {
                throw new RuntimeException();
            }

            this.jsonTracer.trace(jsonWebKey.toJson());
            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.toJson().getString("crv")).contains("NIST P-256");
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            assertThat(jsonWebKey.getPrivateKey()).isNotNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();

            JsonWebKey recoveredJsonWebKey = JsonWebKey.fromJson(jsonWebKey.toJson());
            assertThat(recoveredJsonWebKey.getKid()).isEqualTo(kid);
            if (recoveredJsonWebKey.getPublicKey() instanceof ECPublicKey ecRecPublicKey) {
                assertThat(ecGenPublicKey.equals(ecRecPublicKey)).isTrue();
            } else {
                throw new RuntimeException();
            }
            assertThat(recoveredJsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            if (recoveredJsonWebKey.getPrivateKey() instanceof ECPrivateKey ecRecPrivateKey) {
                assertThat(ecGenPrivateKey.equals(ecRecPrivateKey)).isTrue();
            } else {
                throw new RuntimeException();
            }
            assertThat(recoveredJsonWebKey.getSecretKey()).isNull();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithECPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
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

            if (keyPair.getPublic() instanceof ECPublicKey ecGenPublicKey) {
                tracer.out().printfIndentln("x = %d", ecGenPublicKey.getW().getAffineX());
                tracer.out().printfIndentln("y = %d", ecGenPublicKey.getW().getAffineY());
            } else {
                throw new RuntimeException();
            }
            this.jsonTracer.trace(jsonWebKey.toJson());

            assertThat(jsonWebKey.getKid()).isEqualTo(kid);
            assertThat(jsonWebKey.toJson().getString("crv")).contains("NIST P-256");
            assertThat(jsonWebKey.getPublicKey()).isNotNull();
            assertThat(jsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            assertThat(jsonWebKey.getPrivateKey()).isNull();
            assertThat(jsonWebKey.getSecretKey()).isNull();

            JsonWebKey recoveredJsonWebKey = JsonWebKey.fromJson(jsonWebKey.toJson());
            assertThat(recoveredJsonWebKey.getKid()).isEqualTo(kid);
            if (recoveredJsonWebKey.getPublicKey() instanceof ECPublicKey ecRecPublicKey) {
                assertThat(ecGenPublicKey.equals(ecRecPublicKey)).isTrue();
            } else {
                throw new RuntimeException();
            }
            assertThat(recoveredJsonWebKey.getPublicKey().getAlgorithm()).isEqualTo("EC");
            assertThat(recoveredJsonWebKey.getPrivateKey()).isNull();
            assertThat(recoveredJsonWebKey.getSecretKey()).isNull();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void jwkWithRSAPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "jwkWithRSAPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
            keyPairGenerator.initialize(algorithmParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            if (keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
                if (rsaPublicKey.getParams() instanceof RSAKeyGenParameterSpec rsaKeyGenParameterSpec) {
                    tracer.out().printfIndentln("rsaKeyGenParameterSpec = %s", rsaKeyGenParameterSpec);
                }
            }
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
