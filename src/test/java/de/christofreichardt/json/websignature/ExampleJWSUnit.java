package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonWriter;
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
public class ExampleJWSUnit implements Traceable, WithAssertions {

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
    void dummy() throws IOException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "dummy()");

        try {
            JsonObject jwsHeader = Json.createObjectBuilder()
                    .add("typ", "JWT")
                    .add("alg", "HS256")
                    .build();
            tracer.out().printfIndentln("jwsHeader = %s", jwsHeader);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try ( JsonWriter jsonWriter = Json.createWriter(out)) {
                jsonWriter.write(jwsHeader);
            }
            Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
            String encoded = encoder.encodeToString(out.toByteArray());
            tracer.out().printfIndentln("encoded = %s", encoded);
        } finally {
            tracer.wayout();
        }
    }

    /**
     * Example taken from RFC 7515: JSON Web Signature (JWS).
     * @see<a href="https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1">Example JWS Using HMAC SHA-256</a>
     * 
     * @throws GeneralSecurityException 
     */
    @Test
    void example_1() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "example_1()");

        try {
            // JOSE header
            String header = """
                            {"typ":"JWT",\r
                             "alg":"HS256"}""";

            // UTF-8 encoding
            byte[] headerOctets = header.getBytes(StandardCharsets.UTF_8);
            byte[] expectedHeaderOctets = {123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125};
            tracer.out().printfIndentln("headerOctets = %s", Arrays.toString(headerOctets));
            tracer.out().printfIndentln("expectedHeaderOctets = %s", Arrays.toString(expectedHeaderOctets));
            assertThat(headerOctets).isEqualTo(expectedHeaderOctets);

            // Base64 encoding
            Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
            String headerBase64Encoding = base64UrlEncoder.encodeToString(headerOctets);
            String expectedHeaderBase64Encoding = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
            tracer.out().printfIndentln("headerBase64Encoding = %s", headerBase64Encoding);
            tracer.out().printfIndentln("expectedHeaderBase64Encoding = %s", expectedHeaderBase64Encoding);
            assertThat(headerBase64Encoding).isEqualTo(expectedHeaderBase64Encoding);

            // payload
            String payload = """
                             {"iss":"joe",\r
                              "exp":1300819380,\r
                              "http://example.com/is_root":true}""";

            // UTF-8 encoding
            byte[] payloadOctets = payload.getBytes(StandardCharsets.UTF_8);
            byte[] expectedPayloadOctets = {123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
                48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114,
                117, 101, 125};
            tracer.out().printfIndentln("payloadOctets = %s", Arrays.toString(payloadOctets));
            tracer.out().printfIndentln("expectedPayloadOctets = %s", Arrays.toString(expectedPayloadOctets));
            assertThat(payloadOctets).isEqualTo(expectedPayloadOctets);

            // Base64 encoding
            String payloadBase64Encoding = base64UrlEncoder.encodeToString(payloadOctets);
            String expectedPayloadBase64Encoding = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
            tracer.out().printfIndentln("payloadBase64Encoding = %s", payloadBase64Encoding);
            tracer.out().printfIndentln("expectedPayloadBase64Encoding = %s", expectedPayloadBase64Encoding);
            assertThat(payloadBase64Encoding).isEqualTo(expectedPayloadBase64Encoding);

            // JSON web key
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
            Mac hMac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(keyOctets, "HmacSHA256");
            hMac.init(secretKey);

            // JWS signing input
            String signingInput = headerBase64Encoding + "." + payloadBase64Encoding;
            byte[] signingInputOctets = signingInput.getBytes(StandardCharsets.US_ASCII);
            byte[] expectedSigningInputOctets = {101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
                73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79,
                106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120,
                108, 76, 109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81};
            assertThat(signingInputOctets).isEqualTo(expectedSigningInputOctets);

            // HMacSHA256
            byte[] signatureOctets = hMac.doFinal(signingInputOctets);
            byte[] expectedSignatureOctets = {(byte) 116,(byte) 24,(byte) 223,(byte) 180,(byte) 151,(byte) 153,(byte) 224,(byte) 37,(byte) 79,(byte) 250,(byte) 96,(byte) 125,(byte) 216,
                (byte) 173,(byte) 187,(byte) 186,(byte) 22,(byte) 212,(byte) 37,(byte) 77,(byte) 105,(byte) 214,(byte) 191,(byte) 240,(byte) 91,(byte) 88,(byte) 5,(byte) 88,(byte) 83,
                (byte) 132, (byte) 141, (byte) 121};
            tracer.out().printfIndentln("signatureOctets = %s", Arrays.toString(signatureOctets));
            tracer.out().printfIndentln("expectedSignatureOctets = %s", Arrays.toString(expectedSignatureOctets));
            assertThat(signatureOctets).isEqualTo(expectedSignatureOctets);
            
            // Base 64 encoding
            String encodedSignature = base64UrlEncoder.encodeToString(signatureOctets);
            String exepectedEncodedSignature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            tracer.out().printfIndentln("encodedSignature = %s", encodedSignature);
            assertThat(encodedSignature).isEqualTo(exepectedEncodedSignature);
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
