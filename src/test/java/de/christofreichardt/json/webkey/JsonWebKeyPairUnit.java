package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
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
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .build();
            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
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
            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.kid).isEqualTo(kid);
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withECGenParameterSpec() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECGenParameterSpec()");

        try {
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withAlgorithmParameterSpec(ecGenParameterSpec)
                    .build();
            tracer.out().printfIndentln("jsonWebKeyPair = %s", jsonWebKeyPair);
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withECKeyPairAndKid() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECKeyPairAndKid()");

        try {
            String kid = UUID.randomUUID().toString();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withKeyPair(keyPair)
                    .withKid(kid)
                    .build();
            assertThat(jsonWebKeyPair.algorithmParameterSpec instanceof ECParameterSpec).isTrue();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("EC");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
            assertThat(jsonWebKeyPair.kid).isEqualTo(kid);
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void withRSAKeyGenParameterSpec() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withRSAKeyGenParameterSpec()");

        try {
            AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withAlgorithmParameterSpec(algorithmParameterSpec)
                    .build();
            assertThat(jsonWebKeyPair.keyType).isEqualTo("RSA");
            assertThat(jsonWebKeyPair.keyPair.getPrivate()).isInstanceOf(RSAPrivateKey.class);
            assertThat(jsonWebKeyPair.keyPair.getPublic()).isInstanceOf(RSAPublicKey.class);
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
