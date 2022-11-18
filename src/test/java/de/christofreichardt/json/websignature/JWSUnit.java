package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JWSUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return JWSUnit.this.getCurrentTracer();
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
    void hmac() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmac()");

        try {
            String kid = UUID.randomUUID().toString();
            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of(secretKey)
                    .withKid(kid)
                    .build();
            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "Joe")
                    .add("exp", 1300819380)
                    .build();
            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .secretKey(jsonWebSecretKey)
                    .typ("JWT")
                    .kid(kid)
                    .payload(payload)
                    .sign();

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);

            this.jsonTracer.trace(jsonWebSecretKey.toJson());
            this.jsonTracer.trace(jwsStruct.joseHeader());
            this.jsonTracer.trace(jwsStruct.payload());
            assertThat(jwsStruct.joseHeader().getString("kid")).isEqualTo(kid);
            assertThat(jwsStruct.joseHeader().getString("alg")).isEqualTo("HS256");
            assertThat(jwsStruct.joseHeader().getString("typ")).isEqualTo("JWT");
            assertThat(jwsValidator.validate(secretKey)).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(secretKey)
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ec() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ec()");

        try {
            String kid = UUID.randomUUID().toString();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
                    .withKid(kid)
                    .build();
            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();
            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .keyPair(jsonWebKeyPair)
                    .typ("JWT")
                    .payload(payload)
                    .sign();

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(jwsStruct.joseHeader().getJsonObject("jwk"));

            this.jsonTracer.trace(jsonWebKeyPair.toJson());
            this.jsonTracer.trace(jwsStruct.joseHeader());
            this.jsonTracer.trace(jwsStruct.payload());
            assertThat(jwsStruct.joseHeader().getString("kid")).isEqualTo(kid);
            assertThat(jwsStruct.joseHeader().getString("alg")).isEqualTo("ES256");
            assertThat(jwsStruct.joseHeader().getString("typ")).isEqualTo("JWT");
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
            assertThat(jwsValidator.validate(jsonWebPublicKey.getPublicKey())).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(keyPair.getPublic())
                    .validate();

            assertThat(validated).isTrue();
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
