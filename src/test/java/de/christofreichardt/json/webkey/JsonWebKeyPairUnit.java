package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

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

    @Test
    void withECGenParameterSpec() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withECGenParameterSpec()");

        try {
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withAlgorithmParameterSpec(ecGenParameterSpec)
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
    void withECKeyPairAndKid() throws GeneralSecurityException {
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
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                    .withAlgorithmParameterSpec(algorithmParameterSpec)
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
    void withParameterSpecAfterKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withParameterSpecAfterKeyPair()");

        try {
            String kid = UUID.randomUUID().toString();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> JsonWebKeyPair.of()
                            .withKeyPair(keyPair)
                            .withKid(kid)
                            .withAlgorithmParameterSpec(ecGenParameterSpec)
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
