package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.UUID;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JsonWebPublicKeyUnit implements Traceable, WithAssertions {

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
    void withECPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECPublicKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.of(keyPair.getPublic())
                    .build();
            tracer.out().printfIndentln("jsonWebPublicKey = %s", jsonWebPublicKey);
            assertThat(jsonWebPublicKey.keyType).isEqualTo("EC");
            assertThat(jsonWebPublicKey.algorithmParameterSpec).isInstanceOf(ECParameterSpec.class);
            assertThat(jsonWebPublicKey.publicKey).isInstanceOf(ECPublicKey.class);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withKidAndRSAPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
            assertThat(jsonWebPublicKey.keyType).isEqualTo("RSA");
            assertThat(jsonWebPublicKey.algorithmParameterSpec).isNull();
            assertThat(jsonWebPublicKey.publicKey).isInstanceOf(RSAPublicKey.class);
            assertThat(jsonWebPublicKey.kid).isEqualTo(kid);
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
