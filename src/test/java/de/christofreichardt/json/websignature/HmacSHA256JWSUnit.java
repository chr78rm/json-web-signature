package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 *
 * @author Christof Reichardt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class HmacSHA256JWSUnit implements Traceable, WithAssertions {
    
    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return HmacSHA256JWSUnit.this.getCurrentTracer();
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
    void hmacSha256WithJsonObjects() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmacSha256WithJsonObjects()");

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            HexFormat hexFormat = HexFormat.of().withDelimiter(", ").withPrefix("0x");
            tracer.out().printfIndentln("alg = %s, keysize = %d, octets = %s", secretKey.getAlgorithm(), secretKey.getEncoded().length, hexFormat.formatHex(secretKey.getEncoded()));
            
            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "HS256")
                    .add("typ", "JWT")
                    .build();
            
            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "Joe")
                    .add("exp", 1300819380)
                    .build();
            
            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            tracer.out().printfIndentln("jwsSigner.getStrJoseHeader() = %s", jwsSigner.getStrJoseHeader());
            tracer.out().printfIndentln("jwsSigner.getStrPayload() = %s", jwsSigner.getStrPayload());
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("HmacSHA256");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(secretKey);
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("HmacSHA256");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            tracer.out().printfIndentln("jwsSigner.getStrPayload() = %s", jwsSigner.getStrPayload());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(secretKey)).isTrue();

            JsonObject fakePayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, fakePayload);
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.header(), jwsSigner.sign(secretKey).payload(), compactSerialization.signature());
            jwsValidator = new JWSValidator(fakeSerialization);
            assertThat(jwsValidator.validate(secretKey)).isFalse();
        } finally {
            tracer.wayout();
        }
    }
    
    @Test
    void hmacSha256WithPrettyStringConverter() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmacSha256WithPrettyStringConverter()");

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            HexFormat hexFormat = HexFormat.of().withDelimiter(", ").withPrefix("0x");
            tracer.out().printfIndentln("keysize = %d, octets = %s", secretKey.getEncoded().length, hexFormat.formatHex(secretKey.getEncoded()));
            
            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "HS256")
                    .add("typ", "JWT")
                    .build();
            
            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "Joe")
                    .add("exp", 1300819380)
                    .build();
            
            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload, new PrettyStringConverter());
            tracer.out().printfIndentln("jwsSigner.getStrJoseHeader() = %s", jwsSigner.getStrJoseHeader());
            tracer.out().printfIndentln("jwsSigner.getStrPayload() = %s", jwsSigner.getStrPayload());
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("HmacSHA256");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(secretKey);
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);
            assertThat(compactSerialization).isNotEqualTo(new JWSSigner(joseHeader, payload).sign(secretKey));
            
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("HmacSHA256");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(jwsSigner.getStrJoseHeader());
            tracer.out().printfIndentln("jwsSigner.getStrPayload() = %s", jwsSigner.getStrPayload());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(jwsSigner.getStrPayload());
            assertThat(jwsValidator.validate(secretKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }
    
    /**
     * Example taken from RFC 7515: JSON Web Signature (JWS).
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1">Example JWS Using HMAC SHA-256</a>
     * 
     * @throws GeneralSecurityException 
     */
    @Test
    void hmacSha256WithStrings() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "hmacSha256WithStrings()");

        try {
            String jsonWebKey = """
                                {"kty":"oct",
                                 "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
                                }
                                """;
            String base64EncodedKey;
            try ( JsonReader jsonReader = Json.createReader(new StringReader(jsonWebKey))) {
                base64EncodedKey = jsonReader.readObject().getString("k");
            }
            Base64.Decoder base64UrlDecoder = Base64.getUrlDecoder();
            byte[] keyOctets = base64UrlDecoder.decode(base64EncodedKey);
            SecretKeySpec secretKey = new SecretKeySpec(keyOctets, "HmacSHA256");
            HexFormat hexFormat = HexFormat.of().withDelimiter(", ").withPrefix("0x");
            tracer.out().printfIndentln("keysize = %d, octets = %s", secretKey.getEncoded().length, hexFormat.formatHex(secretKey.getEncoded()));
            
            String strJoseHeader = """
                            {"typ":"JWT",\r
                             "alg":"HS256"}""";
            
            String strPayload = """
                             {"iss":"joe",\r
                              "exp":1300819380,\r
                              "http://example.com/is_root":true}""";
            
            JWSSigner jwsSigner = new JWSSigner(strJoseHeader, strPayload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("HmacSHA256");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(secretKey);
            String expectedSerialization = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            tracer.out().printfIndentln("signature = %s", compactSerialization);
            assertThat(compactSerialization.toString()).isEqualTo(expectedSerialization);
            
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("HmacSHA256");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(strJoseHeader);
            this.jsonTracer.trace(jwsValidator.getJoseHeader());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(strPayload);
            assertThat(jwsValidator.validate(secretKey)).isTrue();
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
                    .add("alg", "HS256")
                    .add("typ", "JWT")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "Joe")
                    .add("exp", 1300819380)
                    .build();

            final JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThatExceptionOfType(InvalidKeyException.class).isThrownBy(() -> jwsSigner.sign(keyPair.getPrivate()));
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
