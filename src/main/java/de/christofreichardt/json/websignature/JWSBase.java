/*
 * Copyright (C) 2022, Christof Reichardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
 * This class provides some core functionality related to creating and validating signatures.
 *
 * @author Christof Reichardt
 */
abstract public class JWSBase {

    static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    static final Map<String, Class<? extends JWSAlgorithm>> ALGO_MAP = Map.of(
            "HS256", HmacSHA256.class, "RS256", SHA256withRSA.class, "ES256", SHA256withECDSA.class, "ES512", SHA512WithECDSA.class
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

    /**
     * Decodes a Base64-URL-encoded string into bytes.
     *
     * @param input the Base64-URL-encoded string
     * @return the decoded bytes
     */
    public static byte[] decodeToBytes(String input) {
        return BASE64_URL_DECODER.decode(input);
    }

    static JsonStructure read(String input) {
        try ( JsonReader jsonReader = Json.createReader(new StringReader(input))) {
            return jsonReader.read();
        }
    }

    record JWSStruct(JsonObject joseHeader, String strJoseHeader, JsonStructure payload, String strPayload) {

        JWSAlgorithm algorithm() {

            String alg = JsonUtils.orElseThrow(joseHeader, "alg", JsonString.class).getString();
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

    /**
     * Returns the string representation of the JOSE header. The raw bytes used for creating the signature
     * will be derived from this string.
     *
     * @return the string representation of the JOSE header.
     */
    public String getStrJoseHeader() {
        return this.jwsStruct.strJoseHeader();
    }

    /**
     * Returns the JOSE Header as {@code JsonObject}.
     *
     * @return the JOSE Header as {@code JsonObject}.
     */
    public JsonObject getJoseHeader() {
        return this.jwsStruct.joseHeader();
    }

    /**
     * Returns the string representation of the actual payload. The raw bytes used for creating the signature
     * will be derived from this string.
     *
     * @return the string representation of the actual payload.
     */
    public String getStrPayload() {
        return this.jwsStruct.strPayload();
    }

    /**
     * Returns the payload as {@code JsonObject}.
     *
     * @return the payload as {@code JsonObject}.
     */
    public JsonStructure getPayload() {
        return this.jwsStruct.payload();
    }
}
