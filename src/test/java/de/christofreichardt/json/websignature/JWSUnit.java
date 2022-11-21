package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
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
    void hmacWithWebKeyAndAllOptions() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmacWithWebKeyAndAllOptions()");

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
                    .webkey(jsonWebSecretKey)
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

            validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebSecretKey)
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ecWithWebkeyAndAllOptions() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ecWithWebkeyAndAllOptions()");

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
                    .webkey(jsonWebKeyPair)
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

            validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebKeyPair.jsonWebPublicKey())
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ecWithKeyPair() throws GeneralSecurityException, FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ecWithKeyPair()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Path path = Path.of("json", "shares", "share-1.json");
            JsonObject share;
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
                share = jsonReader.readObject();
            }

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .key(keyPair)
                    .typ("JOSE")
                    .payload(share)
                    .sign();

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(jwsStruct.joseHeader().getJsonObject("jwk"));

            this.jsonTracer.trace(jwsStruct.joseHeader());
            this.jsonTracer.trace(jwsStruct.payload());

            assertThat(jwsStruct.joseHeader().getString("alg")).isEqualTo("ES256");
            assertThat(jwsStruct.joseHeader().getString("typ")).isEqualTo("JOSE");
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
            assertThat(jwsValidator.validate(jsonWebPublicKey.getPublicKey())).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(keyPair.getPublic())
                    .validate();

            assertThat(validated).isTrue();

            JsonObject falsifiedShare = Json.createObjectBuilder(share)
                    .add("PartitionId", UUID.randomUUID().toString())
                    .build();
            String strFalsifiedShare = JWSBase.encode(falsifiedShare.toString());
            JWSCompactSerialization fakedCompactSerialization = new JWSCompactSerialization(compactSerialization.header(), strFalsifiedShare, compactSerialization.signature());
            JWSBase.JWSStruct fakedJwsStruct = fakedCompactSerialization.makeJWSStruct();

            tracer.out().printfIndentln("fakedCompactSerialization = %s", fakedCompactSerialization);
            this.jsonTracer.trace(fakedJwsStruct.joseHeader());
            this.jsonTracer.trace(fakedJwsStruct.payload());

            boolean falsified = JWS.createValidator()
                    .compactSerialization(fakedCompactSerialization)
                    .key(keyPair.getPublic())
                    .validate();

            assertThat(falsified).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void hmacWithSecretKey() throws GeneralSecurityException, FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmacWithSecretKey()");

        try {
            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();

            Path path = Path.of("json", "shares", "share-1.json");
            JsonObject share;
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
                share = jsonReader.readObject();
            }

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .key(secretKey)
                    .typ("JOSE")
                    .payload(share)
                    .sign();

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);

            this.jsonTracer.trace(jwsStruct.joseHeader());
            this.jsonTracer.trace(jwsStruct.payload());

            assertThat(jwsStruct.joseHeader().getString("alg")).isEqualTo("HS256");
            assertThat(jwsStruct.joseHeader().getString("typ")).isEqualTo("JOSE");
            assertThat(jwsValidator.validate(secretKey)).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(secretKey)
                    .validate();

            assertThat(validated).isTrue();

            SecretKey falseKey = keyGenerator.generateKey();
            boolean falsified = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(falseKey)
                    .validate();

            assertThat(falsified).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    static class RSAPublicKey implements java.security.interfaces.RSAPublicKey {

        final BigInteger modulus;
        final BigInteger exponent;

        public RSAPublicKey(BigInteger modulus, BigInteger exponent) {
            this.modulus = modulus;
            this.exponent = exponent;
        }

        @Override
        public BigInteger getPublicExponent() {
            return this.exponent;
        }

        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }

        @Override
        public BigInteger getModulus() {
            return this.modulus;
        }

    }

    @Test
    void oidcToken() throws FileNotFoundException, GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "oidcToken()");

        try {
            File tokenFile = Path.of(".", "json", "tokens", "test-token.json").toFile();
            JsonObject token;
            try ( JsonReader jsonReader = Json.createReader(new FileReader(tokenFile))) {
                token = jsonReader.readObject();
            }
            this.jsonTracer.trace(token);
            String accessToken = token.getString("access_token");
            JWSCompactSerialization compactSerialization = JWSCompactSerialization.of(accessToken);

            String encodedModulus = "oyfV3I-K1z6O5FRQWJY6tWet2eZpOSs0rdJwv3YiGKrT3BfFfiJqoYAeNDbVXW6vLx-5jhl_RIFsQjGB4R0HiHaMEPvXAneO2brU6yGqwUMA5IAMYU6Km3kfmXgqLyx5mIvwdCHZw-6oHpUnwzIz9wSgiY-qIany-4jKXlJlZ7smo8He1xoRbT74lbmd6LdFCPHcFx3c9PrYJPhdhDK4dqEK02t5OLiaZuOGhKqCHU5RKTaPJzG_ypTlpUywEule7NdL9UDJRFz-IyXOBNTL0Jl2c7HaReHDJrFa13Kk5MlVtrv2mRkMzoJiKdS-stoAzyxcNFj-MSyOo_3mqm299Q";
            String encodedExponent = "AQAB";
            BigInteger modulus, e;
            modulus = new BigInteger(1, JWSBase.decodeToBytes(encodedModulus));
            e = new BigInteger(1, JWSBase.decodeToBytes(encodedExponent));
            RSAPublicKey publicKey = new RSAPublicKey(modulus, e);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(publicKey)
                    .validate();

            assertThat(validated).isTrue();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            boolean falsified = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(keyPair.getPublic())
                    .validate();

            assertThat(falsified).isFalse();
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
