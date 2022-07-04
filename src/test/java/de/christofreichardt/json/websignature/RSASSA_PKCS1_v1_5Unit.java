package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
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
