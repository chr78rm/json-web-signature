package de.christofreichardt.json.websignature;

import de.christofreichardt.json.JsonUtils;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;

/**
 *
 * @author Christof Reichardt
 */
public class JWSBase {

    static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    static final Map<String, Class<? extends JWSAlgorithm>> ALGO_MAP = Map.of(
            "HS256", HmacSHA256.class, "RS256", RSASSA_PKCS1_v1_5.class, "ES256", SHA256withECDSA.class
    );

    static String encode(String input) {
        return BASE64_URL_ENCODER.encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    static String encode(byte[] input) {
        return BASE64_URL_ENCODER.encodeToString(input);
    }

    static String decode(String input) {
        return new String(BASE64_URL_DECODER.decode(input), StandardCharsets.UTF_8);
    }
    
    static byte[] decode(byte[] input) {
        return BASE64_URL_DECODER.decode(input);
    }
    
    static byte[] decodeToBytes(String input) {
        return BASE64_URL_DECODER.decode(input);
    }

    static JsonStructure read(String input) {
        try ( JsonReader jsonReader = Json.createReader(new StringReader(input))) {
            return jsonReader.read();
        }
    }

    record JWSStruct(JsonObject joseHeader, String strJoseHeader, JsonStructure payload, String strPayload) {

        JWSAlgorithm algorithm() {

            String alg = JsonUtils.orElseThrow(joseHeader, "alg", JsonString.class, () -> new IllegalArgumentException("Required header parameter 'alg' is missing.")).getString();
            if (!ALGO_MAP.containsKey(alg)) {
                throw new RuntimeException(String.format("Unsupported algorithm %s.", alg));
            }
            try {
                return ALGO_MAP.get(alg).getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException ex) {
                throw new Error(ex);
            }
        }
    }
    
    final JWSStruct jwsStruct;
    final JWSAlgorithm jwa;

    JWSBase(JWSStruct jwsStruct) {
        this.jwsStruct = jwsStruct;
        this.jwa = this.jwsStruct.algorithm();
    }

    public String getStrJoseHeader() {
        return this.jwsStruct.strJoseHeader();
    }

    public JsonObject getJoseHeader() {
        return this.jwsStruct.joseHeader();
    }

    public String getStrPayload() {
        return this.jwsStruct.strPayload();
    }

    public JsonStructure getPayload() {
        return this.jwsStruct.payload();
    }
}
