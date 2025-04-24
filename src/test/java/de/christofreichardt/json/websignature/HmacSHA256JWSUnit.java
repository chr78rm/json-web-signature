package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
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
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
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
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.encodedHeader(), jwsSigner.sign(secretKey).encodedPayload(), compactSerialization.encodedSignature());
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
     * @throws GeneralSecurityException might be thrown during signing (not really)
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

    @Test
    void oidcToken() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "oidcToken()");

        try {
            // This is extracted from a Keycloak realm JSON export
            String strKeyMaterial = """
                    {
                      "id" : "db786a2e-67d9-4a83-b67c-53f83f50218c",
                      "name" : "hmac-generated",
                      "providerId" : "hmac-generated",
                      "subComponents" : { },
                      "config" : {
                        "kid" : [ "cae8efe1-61c4-4210-8160-41b18fb50d77" ],
                        "active" : [ "true" ],
                        "secretSize" : [ "256" ],
                        "secret" : [ "SsOhd4No_X8So710mA1iSVQhgTZsq04aRm4FmDPjyvpJRsYwS7SlA9hZjyKdcJWthdEtpQ3Ur1Anz7O8mUIWW-jI9qE-FT5z-HINqh2C4WJXh8uNDGLn8gJlMUXIXBahva5YcQtnzJQ-dPSo1FRYMxSzVWTnug4KOX06I1Ir4FQxf9citnBV3HK0M4EY5kPtXI5JtkSW6yBBnBsWyIjPHldpw6aF-u8KkgWuf-we2t7N-k3l6xgSnMGFTQvHTDDh9O_CfzHXjDv_FOZnoKfmXvMwq4_J8at6elynROesL8YR5ydhV3ClUwXkLS7xP_hFN_rh9JCoyvICP8h0Q4hJ3A" ],
                        "priority" : [ "0" ],
                        "enabled" : [ "true" ],
                        "algorithm" : [ "HS256" ]
                      }
                    }""";
            JsonObject keyMaterial;
            try (StringReader stringReader = new StringReader(strKeyMaterial);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                keyMaterial = jsonReader.readObject();
            }
            String secret = keyMaterial.getJsonObject("config")
                    .getJsonArray("secret")
                    .getString(0);
            byte[] secretBytes = JWSBase.decodeToBytes(secret);
            SecretKeySpec secretKey = new SecretKeySpec(secretBytes, "HmacSHA256");
            JsonWebSecretKey jsonWebSecretKey = JsonWebSecretKey.of(secretKey)
                    .build();
            String strOidcToken = """
                    {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjYWU4ZWZlMS02MWM0LTQyMTAtODE2MC00MWIxOGZiNTBkNzcifQ.eyJleHAiOjE3NDU1MDE1NzAsImlhdCI6MTc0NTUwMTI3MCwianRpIjoiMGFhN2RjMWMtNTgwYy00NWRiLTlmOTYtMzA4M2Q1NmQzNzUxIiwiaXNzIjoiaHR0cHM6Ly9uZXh0LWtleWNsb2FrOjg0NDMvcmVhbG1zL3Rlc3QiLCJhdWQiOlsiaHMtMjU2LXRlc3QiLCJhY2NvdW50Il0sInN1YiI6IjBhMDJlMTFjLTc2NTMtNGZhOS1hZWE3LWMyNjA0ZDg1Yjk5NSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImhzLTI1Ni10ZXN0Iiwic2lkIjoiOTlhNDg1YTAtMDI3MC00MGUwLThmMmQtMjdmNWQzZDExOTJkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10ZXN0Iiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsImFwcC10ZXN0ZXIiLCJhcHAtdXNlciJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlRpbmEgVGVzdGVyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdGVyLTAiLCJnaXZlbl9uYW1lIjoiVGluYSIsImZhbWlseV9uYW1lIjoiVGVzdGVyIiwiZW1haWwiOiJ0aW5hLXRlc3RlckB4eXouYWJjIn0.W5TM0JinK6igWO-mBCzHqPEdIFLVoSG-skXri29sWGo",
                        "expires_in": 300,
                        "refresh_expires_in": 1800,
                        "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI5YTY3ZmRkZS03MzFmLTRhODUtYThmOS05NWMwMjAwNTg4YjIifQ.eyJleHAiOjE3NDU1MDMwNzAsImlhdCI6MTc0NTUwMTI3MCwianRpIjoiZGU3ZmQ1ZTMtNTk3NC00YTlhLTk4MDUtNjZiNGYzNjRmMTFiIiwiaXNzIjoiaHR0cHM6Ly9uZXh0LWtleWNsb2FrOjg0NDMvcmVhbG1zL3Rlc3QiLCJhdWQiOiJodHRwczovL25leHQta2V5Y2xvYWs6ODQ0My9yZWFsbXMvdGVzdCIsInN1YiI6IjBhMDJlMTFjLTc2NTMtNGZhOS1hZWE3LWMyNjA0ZDg1Yjk5NSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJocy0yNTYtdGVzdCIsInNpZCI6Ijk5YTQ4NWEwLTAyNzAtNDBlMC04ZjJkLTI3ZjVkM2QxMTkyZCIsInNjb3BlIjoid2ViLW9yaWdpbnMgcm9sZXMgYmFzaWMgZW1haWwgYWNyIHByb2ZpbGUifQ.DTQES5aPjcRguoZEML7247FvscyALYunDJif7sG6HId7vAo6flHyUJ4goC9LP9AjF3PTCu4NW0lRfTOQfric2g",
                        "token_type": "Bearer",
                        "not-before-policy": 0,
                        "session_state": "99a485a0-0270-40e0-8f2d-27f5d3d1192d",
                        "scope": "email profile"
                    }""";
            JsonObject oidcToken;
            try (StringReader stringReader = new StringReader(strOidcToken);
                 JsonReader jsonReader = Json.createReader(stringReader)) {
                oidcToken = jsonReader.readObject();
            }
            String accessToken = oidcToken.getString("access_token");
            JWSCompactSerialization compactSerialization = JWSCompactSerialization.of(accessToken);
            boolean validated = JWS.createValidator()
                    .compactSerialization(compactSerialization)
                    .key(jsonWebSecretKey)
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
