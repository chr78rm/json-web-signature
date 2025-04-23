package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.*;

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

            tracer.out().printfIndentln("kid = %s", kid);
            this.jsonTracer.trace(jsonWebKeyPair.jsonWebPublicKey().toJson());

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
            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(jwsStruct.joseHeader().getJsonObject("jwk"));

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            tracer.out().printfIndentln("compactSerialization.strJoseHeader() = %s", compactSerialization.strJoseHeader());
            tracer.out().printfIndentln("compactSerialization.strPayload() = %s", compactSerialization.strPayload());
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

            String kid = UUID.randomUUID().toString();
            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .key(keyPair)
                    .typ("JOSE")
                    .kid(kid)
                    .payload(share)
                    .sign();
            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(compactSerialization.joseHeader().getJsonObject("jwk"));

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            tracer.out().printfIndentln("jwsStruct.strJoseHeader() = %s", jwsStruct.strJoseHeader());
            tracer.out().printfIndentln("jwsStruct.strPayload() = %s", jwsStruct.strPayload());
            this.jsonTracer.trace(compactSerialization.joseHeader());
            this.jsonTracer.trace(compactSerialization.payload());

            assertThat(compactSerialization.joseHeader().getString("alg")).isEqualTo("ES256");
            assertThat(compactSerialization.joseHeader().getString("typ")).isEqualTo("JOSE");
            assertThat(compactSerialization.joseHeader().getString("kid")).isEqualTo(kid);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();
            assertThat(jwsValidator.validate(jsonWebPublicKey.getPublicKey())).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebPublicKey)
                    .validate();

            assertThat(validated).isTrue();

            JsonObject falsifiedShare = Json.createObjectBuilder(share)
                    .add("PartitionId", UUID.randomUUID().toString())
                    .build();
            String strFalsifiedShare = JWSBase.encode(falsifiedShare.toString());
            JWSCompactSerialization fakedCompactSerialization = new JWSCompactSerialization(compactSerialization.encodedHeader(), strFalsifiedShare, compactSerialization.encodedSignature());
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
    void rs256_oidcToken() throws FileNotFoundException, GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "rs256_OidcToken()");

        try {
            File tokenFile = Path.of(".", "json", "tokens", "test-token.json").toFile();
            JsonObject token;
            try ( JsonReader jsonReader = Json.createReader(new FileReader(tokenFile))) {
                token = jsonReader.readObject();
            }
            this.jsonTracer.trace(token);
            String accessToken = token.getString("access_token");
            JWSCompactSerialization compactSerialization = JWSCompactSerialization.of(accessToken);
            this.jsonTracer.trace(compactSerialization.joseHeader());

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

    @Test
    void es256_oidcToken() throws FileNotFoundException, GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "es256_oidcToken()");

        try {
            File tokenFile = Path.of(".", "json", "tokens", "es256-test-token.json").toFile();
            JsonObject token;
            try ( JsonReader jsonReader = Json.createReader(new FileReader(tokenFile))) {
                token = jsonReader.readObject();
            }
            this.jsonTracer.trace(token);
            String accessToken = token.getString("access_token");
            JWSCompactSerialization compactSerialization = JWSCompactSerialization.of(accessToken);
            this.jsonTracer.trace(compactSerialization.joseHeader());

            String jwk = """
                  {
                      "kid": "Rf1c0xrE03Ud68kawPN_ZGcZ9GUNm1Au1gI0ieqxC44",
                      "kty": "EC",
                      "alg": "ES256",
                      "use": "sig",
                      "x5c": [
                          "MIIBCjCBsQIGAZWqftezMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBHRlc3QwHhcNMjUwMzE4MTgyMTM0WhcNMzUwMzE4MTgyMzE0WjAPMQ0wCwYDVQQDDAR0ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERVIMLIqI9KwvB1vxAlCdqGlot3IZJqR8F3f83zSWZahQAONXk269y2rQOKVHD9PJ6gHI0vWHospNHQGLfLdVuTAKBggqhkjOPQQDAgNIADBFAiABwwAEqnaNutBRr2MZ51/RGpzrm9JZ+KAJn7B+iUGZfgIhAO5zOVGWj0scaaHjsQ0S62Z0OUApFc86ZupYhpzx4Hln"
                      ],
                      "x5t": "rMTfRooBj4adjoTL_1C1mwBvS9E",
                      "x5t#S256": "MCQIkq2VQ4OKBmJ3brJjvIc2sNGnfLwO8g-yf3SHcJ8",
                      "crv": "P-256",
                      "x": "RVIMLIqI9KwvB1vxAlCdqGlot3IZJqR8F3f83zSWZag",
                      "y": "UADjV5Nuvctq0DilRw_TyeoByNL1h6LKTR0Bi3y3Vbk"
                  }
                  """;
            JsonObject webKey;
            try (StringReader stringReader = new StringReader(jwk);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                webKey = jsonReader.readObject();
            }
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(webKey);
            this.jsonTracer.trace(jsonWebPublicKey.toJson());

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebPublicKey)
                    .validate();
            assertThat(validated).isTrue();

            String wrongJwk = """
                    {
                        "kid": "EQYh6_gqSDRYeFIpg2nZYBETLU_1vCoWTPJ-3vFekeo",
                        "kty": "EC",
                        "alg": "ES256",
                        "use": "sig",
                        "x5c": [
                            "MIIBCjCBsQIGAZWqftfyMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBHRlc3QwHhcNMjUwMzE4MTgyMTM0WhcNMzUwMzE4MTgyMzE0WjAPMQ0wCwYDVQQDDAR0ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPXYJcjFUWd5POqbaCNmvQoh8SNWxEMQMsc2Ow/CjVh5WZpAXfavI8Ir3QptjCmhDeRL22EjHz32MBpViM+Lz8zAKBggqhkjOPQQDAgNIADBFAiEAnivDFtAnB3osLdP04mIMaZL3ECnmL59b/g+RLDvVB4ACIHpcMA0ywQ3xK5awkFNsbpJTSqbKOPHqSaqtvF0wx8uy"
                        ],
                        "x5t": "dp88XIPNKcH4gqnhkZefD5Ftrx0",
                        "x5t#S256": "jhM4n_IzuJrBN5QrWnwAF1i8WPqBIMJq2Q5avZJWmRc",
                        "crv": "P-256",
                        "x": "PXYJcjFUWd5POqbaCNmvQoh8SNWxEMQMsc2Ow_CjVh4",
                        "y": "VmaQF32ryPCK90KbYwpoQ3kS9thIx899jAaVYjPi8_M"
                    }
                    """;
            JsonObject wrongWebKey;
            try (StringReader stringReader = new StringReader(wrongJwk);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                wrongWebKey = jsonReader.readObject();
            }
            JsonWebPublicKey wrongJsonWebPublicKey = JsonWebPublicKey.fromJson(wrongWebKey);
            this.jsonTracer.trace(wrongJsonWebPublicKey.toJson());

            boolean falsified = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(wrongJsonWebPublicKey)
                    .validate();
            assertThat(!falsified).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void hmacWithLiteralStringPayload() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "exit()");

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

            String share =
                    """
                    {
                        "PartitionId": "f14434bc-c852-47d8-8001-8f349f0b9408",
                        "Prime": 77036549738719732710990429556180762025039,
                        "Threshold": 4,
                        "SharePoints": [
                            {
                                "SharePoint": {
                                    "x": 22766610275390711977223194921953354317543,
                                    "y": 54083401924870413023277357643502454671674
                                }
                            }
                        ]
                    }
                    """;

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebSecretKey)
                    .typ("JWT")
                    .kid(kid)
                    .payload(share)
                    .sign();
            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            tracer.out().printfIndentln("jwsStruct.strJoseHeader() = %s", jwsStruct.strJoseHeader());
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
    void rsaWithPrettyPrintConverter() throws GeneralSecurityException, FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "rsaWithPrettyPrintConverter()");

        try {
            final int BIT_LENGTH = 32, CERTAINTY = 64, KEY_SIZE = 3072;
            BigInteger e = new BigInteger(BIT_LENGTH, CERTAINTY, SecureRandom.getInstance("SHA1PRNG"));
            AlgorithmParameterSpec algorithmParameterSpec = new RSAKeyGenParameterSpec(KEY_SIZE, e);
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(algorithmParameterSpec)
                    .build();

            Path path = Path.of("json", "shares", "share-1.json");
            JsonObject share;
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
                share = jsonReader.readObject();
            }

            final String TYP = "JOSE";
            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebKeyPair)
                    .typ(TYP)
                    .payload(share)
                    .sign(new PrettyStringConverter());
            JWSBase.JWSStruct jwsStruct = compactSerialization.makeJWSStruct();
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(jwsStruct.joseHeader().getJsonObject("jwk"));

            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            tracer.out().printfIndentln("compactSerialization.strJoseHeader() = %s", compactSerialization.strJoseHeader());
            tracer.out().printfIndentln("compactSerialization.strPayload() = %s", compactSerialization.strPayload());

            assertThat(jwsStruct.joseHeader().getString("alg")).isEqualTo("RS256");
            assertThat(jwsStruct.joseHeader().getString("typ")).isEqualTo(TYP);
            assertThat(jwsValidator.validate(jsonWebPublicKey.getPublicKey())).isTrue();

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebKeyPair.jsonWebPublicKey())
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    static class RSAPrivateKey implements java.security.interfaces.RSAPrivateKey {

        final BigInteger modulus;
        final BigInteger privateExponent;

        public RSAPrivateKey(BigInteger modulus, BigInteger privateExponent) {
            this.modulus = modulus;
            this.privateExponent = privateExponent;
        }

        @Override
        public BigInteger getPrivateExponent() {
            return this.privateExponent;
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

    /**
     * Example taken from RFC 7515: JSON Web Signature (JWS).
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.2">A.2 Example JWS Using RSASSA-PKCS1-v1_5 SHA-256</a>
     */
    @Test
    void rsaWithLiteralHeaderAndPayload() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "rsaWithLiteralHeaderAndPayload()");

        try {
            BigInteger modulus = new BigInteger("20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601");
            BigInteger d = new BigInteger("2358310989939619510179986262349936882924652023566213765118606431955566700506538911356936879137503597382515919515633242482643314423192704128296593672966061810149316320617894021822784026407461403384065351821972350784300967610143459484324068427674639688405917977442472804943075439192026107319532117557545079086537982987982522396626690057355718157403493216553255260857777965627529169195827622139772389760130571754834678679842181142252489617665030109445573978012707793010592737640499220015083392425914877847840457278246402760955883376999951199827706285383471150643561410605789710883438795588594095047409018233862167884701");
            RSAPrivateKey privateKey = new RSAPrivateKey(modulus, d);
            BigInteger e = new BigInteger("65537");
            RSAPublicKey publicKey = new RSAPublicKey(modulus, e);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            String strJoseHeader = """
                                   {"alg":"RS256"}""";

            String strPayload = """
                                {"iss":"joe",\r
                                 "exp":1300819380,\r
                                 "http://example.com/is_root":true}""";

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .key(keyPair)
                    .header(strJoseHeader)
                    .payload(strPayload)
                    .sign();

            tracer.out().printfIndentln("compactSerialization.encodedHeader() = %s", compactSerialization.encodedHeader());
            tracer.out().printfIndentln("Decoded (original) header = %s", JWSBase.decode(compactSerialization.encodedHeader()));
            tracer.out().printfIndentln("compactSerialization.encodedPayload() = %s", compactSerialization.encodedPayload());
            tracer.out().printfIndentln("Decoded (original) payload = %n%s", JWSBase.decode(compactSerialization.encodedPayload()));

            String expectedSerialization = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
            tracer.out().printfIndentln("signature = %s", compactSerialization);
            assertThat(compactSerialization.toString()).isEqualTo(expectedSerialization);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(publicKey)
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ambigousKidsWithSecretKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ambigousKidsWithSecretKey()");

        try {
            String kid = UUID.randomUUID().toString();

            tracer.out().printfIndentln("kid = %s", kid);

            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of(secretKey)
                    .withKid(kid)
                    .build();

            String share =
                    """
                    {
                        "PartitionId": "f14434bc-c852-47d8-8001-8f349f0b9408",
                        "Prime": 77036549738719732710990429556180762025039,
                        "Threshold": 4,
                        "SharePoints": [
                            {
                                "SharePoint": {
                                    "x": 22766610275390711977223194921953354317543,
                                    "y": 54083401924870413023277357643502454671674
                                }
                            }
                        ]
                    }
                    """;

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(
                            () -> JWS.createSignature()
                                    .webkey(jsonWebSecretKey)
                                    .typ("JWT")
                                    .kid(null)
                                    .payload(share)
                                    .sign()
                    )
                    .withMessage("Ambigous kids.");

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(
                            () -> JWS.createSignature()
                                    .webkey(jsonWebSecretKey)
                                    .typ("JWT")
                                    .kid(UUID.randomUUID().toString())
                                    .payload(share)
                                    .sign()
                    )
                    .withMessage("Ambigous kids.");

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebSecretKey)
                    .typ("JWT")
                    .kid(kid)
                    .payload(share)
                    .sign();

            tracer.out().printfIndentln("signature = %s", compactSerialization);
            this.jsonTracer.trace(compactSerialization.joseHeader());

            assertThat(compactSerialization.joseHeader().getString("kid")).isEqualTo(kid);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebSecretKey)
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void ambigousKidsWithKeyPair() throws GeneralSecurityException, FileNotFoundException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "ambigousKidsWithKeyPair()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String kid = UUID.randomUUID().toString();
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
                    .withKid(kid)
                    .build();

            this.jsonTracer.trace(jsonWebKeyPair.toJson());

            Path path = Path.of("json", "shares", "share-1.json");
            JsonObject share;
            try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
                share = jsonReader.readObject();
            }

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() ->
                            JWS.createSignature()
                                    .webkey(jsonWebKeyPair)
                                    .typ("JOSE")
                                    .kid(UUID.randomUUID().toString())
                                    .payload(share)
                                    .sign()
                    )
                    .withMessage("Ambigous kids.");

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() ->
                            JWS.createSignature()
                                    .webkey(jsonWebKeyPair)
                                    .typ("JOSE")
                                    .kid(null)
                                    .payload(share)
                                    .sign()
                    )
                    .withMessage("Ambigous kids.");

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebKeyPair)
                    .typ("JOSE")
                    .kid(kid)
                    .payload(share)
                    .sign();

            tracer.out().printfIndentln("signature = %s", compactSerialization);
            this.jsonTracer.trace(compactSerialization.joseHeader());

            assertThat(compactSerialization.joseHeader().getString("kid")).isEqualTo(kid);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebKeyPair.jsonWebPublicKey())
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void delayedKidWithSecretKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "delayedKidWithSecretKey()");

        try {
            String kid = UUID.randomUUID().toString();

            tracer.out().printfIndentln("kid = %s", kid);

            final int KEY_SIZE = 1024;
            final String ALGORITHM = "HmacSHA256";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of(secretKey)
                    .build();

            String share =
                    """
                    {
                        "PartitionId": "f14434bc-c852-47d8-8001-8f349f0b9408",
                        "Prime": 77036549738719732710990429556180762025039,
                        "Threshold": 4,
                        "SharePoints": [
                            {
                                "SharePoint": {
                                    "x": 22766610275390711977223194921953354317543,
                                    "y": 54083401924870413023277357643502454671674
                                }
                            }
                        ]
                    }
                    """;

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebSecretKey)
                    .typ("JWT")
                    .kid(kid)
                    .payload(share)
                    .sign();

            tracer.out().printfIndentln("signature = %s", compactSerialization);
            this.jsonTracer.trace(compactSerialization.joseHeader());

            assertThat(compactSerialization.joseHeader().getString("kid")).isEqualTo(kid);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebSecretKey)
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void delayedKidWithKeyPair() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "delayedKidWithKeyPair()");

        try {
            String kid = UUID.randomUUID().toString();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSCompactSerialization compactSerialization = JWS.createSignature()
                    .webkey(jsonWebKeyPair)
                    .typ("JWT")
                    .kid(kid)
                    .payload(payload)
                    .sign();

            tracer.out().printfIndentln("signature = %s", compactSerialization);
            this.jsonTracer.trace(compactSerialization.joseHeader());

            assertThat(compactSerialization.joseHeader().getString("kid")).isEqualTo(kid);

            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebKeyPair.jsonWebPublicKey())
                    .validate();

            assertThat(validated).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class Examples {

        @Test
        void withDefaultWebKeyAndAllHeaderParams() throws GeneralSecurityException {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("void", this, "withDefaultWebKeyAndAllHeaderParams()");

            try {
                JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of()
                        .withSecureRandom(SecureRandom.getInstanceStrong())
                        .build();

                JWSUnit.this.jsonTracer.trace(jsonWebKeyPair.toJson());

                String strPayload = """
                        {
                            "iss": "OpenIDConnect-Provider",
                            "exp": 1744732996,
                            "aud": "Protected App",
                            "jti": "e575fa68-4d24-4398-a2c8-87432d8aa57b",
                            "name": "Tina Tester",
                            "email": "tina-tester@xyz.abc",
                            "roles": [
                                "app-user",
                                "app-tester"
                            ]
                        }
                        """;

                JsonObject payload;
                try (StringReader stringReader = new StringReader(strPayload);
                     JsonReader jsonReader = Json.createReader(stringReader)) {
                    payload = jsonReader.readObject();
                }

                JWSUnit.this.jsonTracer.trace(payload);

                String kid = UUID.randomUUID().toString();
                JWSCompactSerialization compactSerialization = JWS.createSignature()
                        .webkey(jsonWebKeyPair)
                        .typ("JWT")
                        .kid(kid)
                        .payload(payload)
                        .sign();

                tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
                tracer.out().printfIndentln("strJoseHeader = %s", compactSerialization.strJoseHeader());
                tracer.out().printfIndentln("strPayload = %s", compactSerialization.strPayload());

                boolean validated = JWS.createValidator()
                        .compactSerialization(compactSerialization)
                        .key(jsonWebKeyPair.jsonWebPublicKey())
                        .validate();
                assert validated;

                compactSerialization = JWS.createSignature()
                        .webkey(jsonWebKeyPair)
                        .typ("JWT")
                        .kid(kid)
                        .payload(payload)
                        .sign(new PrettyStringConverter());

                tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
                tracer.out().printfIndentln("strJoseHeader = %s", compactSerialization.strJoseHeader());
                tracer.out().printfIndentln("strPayload = %s", compactSerialization.strPayload());

                validated = JWS.createValidator()
                        .compactSerialization(compactSerialization)
                        .key(jsonWebKeyPair.jsonWebPublicKey())
                        .validate();
                assert validated;

                compactSerialization = JWS.createSignature()
                        .webkey(jsonWebKeyPair)
                        .typ("JWT")
                        .kid(kid)
                        .payload(strPayload)
                        .sign();

                tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
                tracer.out().printfIndentln("strJoseHeader = %s", compactSerialization.strJoseHeader());
                tracer.out().printfIndentln("strPayload = %s", compactSerialization.strPayload());

                validated = JWS.createValidator()
                        .compactSerialization(compactSerialization)
                        .key(jsonWebKeyPair.jsonWebPublicKey())
                        .validate();
                assert validated;
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
