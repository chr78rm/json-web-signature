package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.JsonTracer;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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

/**
 *
 * @author Christof Reichardt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class RSASSA_PKCS1_v1_5Unit implements Traceable, WithAssertions {
    
    class MyJsonTracer extends JsonTracer {

        @Override
        public AbstractTracer getCurrentTracer() {
            return RSASSA_PKCS1_v1_5Unit.this.getCurrentTracer();
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

    /**
     * Example taken from RFC 7515: JSON Web Signature (JWS).
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.2">A.2 Example JWS Using RSASSA-PKCS1-v1_5 SHA-256</a>
     * 
     * @throws GeneralSecurityException 
     */
    @Test
    void withStrings() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withStrings()");

        try {
            String strJsonWebKey = """
                                   {"kty":"RSA",
                                      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
                                      "e":"AQAB",
                                      "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
                                      "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
                                      "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
                                   }
                                   """;
            BigInteger modulus, p, q, d, e;
            try ( JsonReader jsonReader = Json.createReader(new StringReader(strJsonWebKey))) {
                JsonObject jsonWebKey = jsonReader.readObject();
                modulus = new BigInteger(1, JWSBase.decodeToBytes(jsonWebKey.getString("n")));
                p = new BigInteger(1, JWSBase.decodeToBytes(jsonWebKey.getString("p")));
                q = new BigInteger(1, JWSBase.decodeToBytes(jsonWebKey.getString("q")));
                d = new BigInteger(1, JWSBase.decodeToBytes(jsonWebKey.getString("d")));
                e = new BigInteger(1, JWSBase.decodeToBytes(jsonWebKey.getString("e")));
            }
            tracer.out().printfIndentln("modulus = %s", modulus);
            tracer.out().printfIndentln("p = %s", p);
            tracer.out().printfIndentln("q = %s", q);
            tracer.out().printfIndentln("d = %s", d);
            tracer.out().printfIndentln("e = %s", e);
            assertThat(p.multiply(q)).isEqualTo(modulus);
            assertThat(p.isProbablePrime(100)).isTrue();
            assertThat(q.isProbablePrime(100)).isTrue();
            assertThat(d.multiply(e).mod((p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)))).isEqualTo(BigInteger.ONE);
            RSAPrivateKey privateKey = new RSAPrivateKey(modulus, d);

            String strJoseHeader = """
                                   {"alg":"RS256"}""";

            String strPayload = """
                                {"iss":"joe",\r
                                 "exp":1300819380,\r
                                 "http://example.com/is_root":true}""";
            
            JWSSigner jwsSigner = new JWSSigner(strJoseHeader, strPayload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withRSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(privateKey);
            String expectedSerialization = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
            tracer.out().printfIndentln("signature = %s", compactSerialization);
            assertThat(compactSerialization.toString()).isEqualTo(expectedSerialization);
            
            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA256withRSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(strJoseHeader);
            assertThat(jwsValidator.getStrPayload()).isEqualTo(strPayload);
            RSAPublicKey publicKey = new RSAPublicKey(modulus, e);
            assertThat(jwsValidator.validate(publicKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }
    
    @Test
    void withJsonObjects() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "withJsonObjects()");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            tracer.out().printfIndentln("keyPair.getPrivate().getClass().getName() = %s", keyPair.getPrivate().getClass().getName());
            tracer.out().printfIndentln("keyPair.getPublic().getClass().getName() = %s", keyPair.getPublic().getClass().getName());
            if (keyPair.getPublic() instanceof java.security.interfaces.RSAPublicKey publicKey) {
                tracer.out().printfIndentln("rsaPublicKey.getParams() = %s", publicKey.getParams());
            }

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "RS256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThat(jwsSigner.jwa.algorithm()).isEqualTo("SHA256withRSA");
            JWSCompactSerialization compactSerialization = jwsSigner.sign(keyPair.getPrivate());
            tracer.out().printfIndentln("compactSerialization = %s", compactSerialization);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            assertThat(jwsValidator.jwa.algorithm()).isEqualTo("SHA256withRSA");
            assertThat(jwsValidator.getStrJoseHeader()).isEqualTo(joseHeader.toString());
            assertThat(jwsValidator.getStrPayload()).isEqualTo(payload.toString());
            assertThat(jwsValidator.validate(keyPair.getPublic())).isTrue();

            JsonObject fakePayload = Json.createObjectBuilder()
                    .add("iss", "harry")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            jwsSigner = new JWSSigner(joseHeader, fakePayload);
            JWSCompactSerialization fakeSerialization = new JWSCompactSerialization(compactSerialization.header(), jwsSigner.sign(keyPair.getPrivate()).payload(), compactSerialization.signature());
            jwsValidator = new JWSValidator(fakeSerialization);
            assertThat(jwsValidator.validate(keyPair.getPublic())).isFalse();
        } finally {
            tracer.wayout();
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
            tracer.out().printfIndentln("modulus = %d", modulus);
            tracer.out().printfIndentln("e = %d", e);

            JWSValidator jwsValidator = new JWSValidator(compactSerialization);
            this.jsonTracer.trace(jwsValidator.getJoseHeader());
            this.jsonTracer.trace(jwsValidator.getPayload());
            RSAPublicKey publicKey = new RSAPublicKey(modulus, e);
            assertThat(jwsValidator.validate(publicKey)).isTrue();
        } finally {
            tracer.wayout();
        }
    }

    @Test
    void invalidKey() throws GeneralSecurityException {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "invalidKey()");

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();

            JsonObject joseHeader = Json.createObjectBuilder()
                    .add("alg", "RS256")
                    .build();

            JsonObject payload = Json.createObjectBuilder()
                    .add("iss", "joe")
                    .add("exp", 1300819380)
                    .add("http://example.com/is_root", "true")
                    .build();

            final JWSSigner jwsSigner = new JWSSigner(joseHeader, payload);
            assertThatExceptionOfType(InvalidKeyException.class).isThrownBy(() -> jwsSigner.sign(secretKey));
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
