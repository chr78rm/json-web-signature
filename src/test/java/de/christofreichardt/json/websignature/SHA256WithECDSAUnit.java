package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebPublicKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.StringReader;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.*;

/**
 *
 * @author Christof Reichardt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SHA256WithECDSAUnit implements Traceable, WithAssertions {

    class MyJsonTracer extends JsonTracer {
        @Override
        public AbstractTracer getCurrentTracer() {
            return SHA256WithECDSAUnit.this.getCurrentTracer();
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

    /**
     * The JSON Web Algorithm (JWA) 'ES256' specified in RFC 7518 requires the use of the NIST curve P-256. The test case prints the relevant curve parameter which can be checked against
     * the specification of the NIST. 
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">3.4. Digital Signature with ECDSA</a>
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">Digital Signature Standard (DSS)</a>
     * 
     * @throws GeneralSecurityException indicates problems when generating the key pair
     */
    @RepeatedTest(25)
    void withJsonObjects() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withJsonObjects()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
            tracer.out().printfIndentln("s = %s", ecPrivateKey.getS());
            tracer.out().printfIndentln("ecParameterSpec = %s", ecParameterSpec);
            tracer.out().printfIndentln("n = %s", ecParameterSpec.getOrder());
            tracer.out().printfIndentln("bitlength(%d) = %d", ecParameterSpec.getOrder(), ecParameterSpec.getOrder().bitLength());
            tracer.out().printfIndentln("cofactor = %d", ecParameterSpec.getCofactor());
            if (ecParameterSpec.getCurve().getField() instanceof ECFieldFp ecFieldFp) {
                tracer.out().printfIndentln("curve[a=%s, b=%s, p=%d]", 
                        ecParameterSpec.getCurve().getA().subtract(ecFieldFp.getP()), ecParameterSpec.getCurve().getB().toString(16), ecFieldFp.getP());
                tracer.out().printfIndentln("generator[x=%s, y=%s]", 
                        ecParameterSpec.getGenerator().getAffineX().toString(16), ecParameterSpec.getGenerator().getAffineY().toString(16));
            }

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();

            JsonObject fakePayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, fakePayload);
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.encodedHeader(), jwsSigner.sign(keyPair.getPrivate()).encodedPayload(), compactSerialization.encodedSignature());
            jwsValidator = new JWSValidator(fakeSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    @RepeatedTest(25)
    void withJsonWebKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withJsonWebKey()");

        try {
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(JsonWebKey.SECP256R1)
                    .withSecureRandom(SecureRandom.getInstanceStrong())
                    .build();

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(jsonWebKeyPair.getKeyPair().getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey())).isTrue();

            JsonObject fakePayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, fakePayload);
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.encodedHeader(), jwsSigner.sign(jsonWebKeyPair.getKeyPair().getPrivate()).encodedPayload(), compactSerialization.encodedSignature());
            jwsValidator = new JWSValidator(fakeSerialization);
            assertThat(jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey())).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void invalidKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "invalidKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            final JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThatExceptionOfType(InvalidKeyException.class).isThrownBy(() -> jwsSigner.sign(keyPair.getPrivate()));
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void invalidECKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "invalidECKey()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp521r1");
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "ES256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withECDSA");
            assertThatExceptionOfType(InvalidKeyException.class).isThrownBy(() -> jwsSigner.sign(keyPair.getPrivate()));
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void oidcToken() throws FileNotFoundException, GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "oidcToken()");

        try {
            File tokenFile = Path.of(".", "json", "tokens", "es256-test-token.json").toFile();
            JsonObject token;
            try ( JsonReader jsonReader = Json.createReader(new FileReader(tokenFile))) {
                token = jsonReader.readObject();
            }
            this.jsonTracer.trace(token);
            String accessToken = token.getString("access_token");
            JWSCompactSerialization compactSerialization = JWSCompactSerialization.of(accessToken);

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
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            this.jsonTracer.trace(jwsValidator.getJoseHeader());
            this.jsonTracer.trace(jwsValidator.getPayload());
            assertThat(jwsValidator.validate(jsonWebPublicKey.getPublicKey())).isTrue();

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
            assertThat(jwsValidator.validate(wrongJsonWebPublicKey.getPublicKey())).isFalse();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void exampleFromRFC7515() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "exampleFromRFC7515()");

        try {
            String strHeader = """
                    {"alg":"ES256"}""";
            String strPayload = """
                    {"iss":"joe",\r
                     "exp":1300819380,\r
                     "http://example.com/is_root":true}""";
            String strKeyPair = """
                    {"kty":"EC",
                     "crv":"P-256",
                     "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                     "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                     "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
                    }""";
            JsonObject webKey;
            try (StringReader stringReader = new StringReader(strKeyPair);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                webKey = jsonReader.readObject();
            }
            JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.fromJson(webKey);
            JWSSigner jwsSigner = new JWSSigner(strHeader, strPayload);
            JWSCompactSerialization compactSerialization = jwsSigner.sign(jsonWebKeyPair.getKeyPair().getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            assert Objects.equals(compactSerialization.encodedHeader(), "eyJhbGciOiJFUzI1NiJ9");
            assert Objects.equals(compactSerialization.encodedPayload(), "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assert jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey());

            byte[] r = {14, (byte) 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, (byte) 212, 2, (byte) 163, (byte) 178, 40, 3, 58, (byte) 249, 124, 126, 23, (byte) 129,
                    (byte) 154, (byte) 195, 22, (byte) 158, (byte) 166, 101};
            byte[] s = {(byte) 197, 10, 7, (byte) 211, (byte) 140, 60, 112, (byte) 229, (byte) 216, (byte) 241, 45, (byte) 175, 8, 74, 84, (byte) 128, (byte) 166, 101, (byte) 144,
                    (byte) 197, (byte) 242, (byte) 147, 80, (byte) 154, (byte) 143, 63, 127, (byte) 138, (byte) 131, (byte) 163, 84, (byte) 213};
            tracer.out().printfIndentln("len(r) = %d, len(s) = %d", r.length, s.length);
            byte[] signature = new byte[64];
            System.arraycopy(r, 0, signature, 0, r.length);
            System.arraycopy(s, 0, signature, 32, s.length);
            String encodedSignature = JWSBase.encode(signature);
            tracer.out().printfIndentln("encodedSignature = %s", encodedSignature);
            assert Objects.equals(encodedSignature, "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
            JWSCompactSerialization compactSerializationByAppendixA3 = JWSCompactSerialization.of(
                    "%s.%s.%s".formatted(compactSerialization.encodedHeader(), compactSerialization.encodedPayload(), encodedSignature)
            );
            jwsValidator = new JWSValidator(compactSerializationByAppendixA3);
            assert jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey());

            assert signature[5] == 99;
            signature[5] = 67;
            String fakedSignature = JWSBase.encode(signature);
            JWSCompactSerialization fakedcompactSerialization = JWSCompactSerialization.of(
                    "%s.%s.%s".formatted(compactSerialization.encodedHeader(), compactSerialization.encodedPayload(), fakedSignature)
            );
            jwsValidator = new JWSValidator(fakedcompactSerialization);
            assert !jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey());

            String fakePayload = """
                    {"iss":"donald",\r
                     "exp":1300819380,\r
                     "http://example.com/is_root":true}""";
            JWSCompactSerialization anotherFakedcompactSerialization = JWSCompactSerialization.of(
                    "%s.%s.%s".formatted(compactSerialization.encodedHeader(), JWSBase.encode(fakePayload), encodedSignature)
            );
            jwsValidator = new JWSValidator(anotherFakedcompactSerialization);
            assert !jwsValidator.validate(jsonWebKeyPair.jsonWebPublicKey().getPublicKey());
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
