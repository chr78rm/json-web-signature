package de.christofreichardt.json.websignature;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonStructure;

/**
 *
 * @author Christof Reichardt
 */
public class JWSBase {

    static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    static final Map<String, Class<? extends JWSAlgorithm>> ALGO_MAP = Map.of("HS256", HmacSHA256.class, "RS256", RSASSA_PKCS1_v1_5.class);

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

    static JsonStructure read(String input) {
        try ( JsonReader jsonReader = Json.createReader(new StringReader(input))) {
            return jsonReader.read();
        }
    }

    static record JWSStruct(JsonObject joseHeader, String strJoseHeader, JsonStructure payload, String strPayload) {

        final JWSAlgorithm algorithm() {
            if (!this.joseHeader.containsKey("alg")) {
                throw new RuntimeException("Required header parameter 'alg' is missing.");
            }
            String alg = this.joseHeader.getString("alg");
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
