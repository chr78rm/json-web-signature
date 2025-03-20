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

package de.christofreichardt.json.webkey;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

/**
 * Base class for JSON web keys.
 *
 * @author Christof Reichardt
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517 (JSON Web Key)</a>
 */
abstract public sealed class JsonWebKey implements Traceable permits JsonWebKeyPair, JsonWebPublicKey, JsonWebSecretKey {

    static final Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256");
    public static final Map<String, ECParameterSpec> EC_PARAMETER_SPEC_MAP;
    static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();

    static {
        BigInteger p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
        ECFieldFp ecFieldFp = new ECFieldFp(p);
        BigInteger a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
        BigInteger b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
        EllipticCurve secp256r1 = new EllipticCurve(ecFieldFp, a, b);
        ECPoint generator = new ECPoint(
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
        );
        BigInteger order = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");
        ECParameterSpec ecParameterSpec = new NamedECParameterSpec("secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)", secp256r1, generator, order, 1);
        EC_PARAMETER_SPEC_MAP = Map.of("secp256r1", ecParameterSpec);
    }

    /**
     * Base class for all {@code JsonWebKey.Builder}s.
     * @param <T> the type of the {@code Builder} subclass.
     */
    abstract public static class Builder<T extends Builder<T>> {
        String kid = null;

        public T withKid(String kid) {
            this.kid = kid;
            @SuppressWarnings("unchecked")
            T t = (T) this;

            return t;
        }

        abstract JsonWebKey build() throws GeneralSecurityException;
    }

    /**
     * Generic method to create a {@code JsonWebKey} from a JSON representation.
     *
     * @param webKeyView the JSON representation.
     * @param clazz the actual {@code JsonWebKey} class, could be a {@code JsonWebKeyPair}, {@code JsonWebPublicKey} or {@code JsonWebSecretKey}.
     * @return a {@code JsonWebKey} object.
     * @param <T> the type of the {@code JsonWebKey} class, modeled by the given {@code Class} object.
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    public static <T extends JsonWebKey> T fromJson(JsonObject webKeyView, Class<T> clazz) throws GeneralSecurityException {
        if (JsonWebPublicKey.class.isAssignableFrom(clazz)) {
            @SuppressWarnings("unchecked")
            T t = (T) JsonWebPublicKey.fromJson(webKeyView);
            return t;
        } else if (JsonWebKeyPair.class.isAssignableFrom(clazz)) {
            @SuppressWarnings("unchecked")
            T t = (T) JsonWebKeyPair.fromJson(webKeyView);
            return t;
        } else if (JsonWebSecretKey.class.isAssignableFrom(clazz)) {
            @SuppressWarnings("unchecked")
            T t = (T) JsonWebSecretKey.fromJson(webKeyView);
            return t;
        } else {
            throw new UnsupportedOperationException();
        }
    }

    final String kid;
    final String keyType;

    /**
     * Returns the "kid" (Key ID) parameter.
     *
     * @return the key id, may be null.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">Section 4.5 of RFC 7517</a>
     */
    public String getKid() {
        return kid;
    }

    /**
     * Returns the required "kty" (Key Type) parameter.
     *
     * @return the key type.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.1">Section 4.1 of RFC 7517</a>
     */
    public String getKeyType() {
        return keyType;
    }

    /**
     * Base class constructor used by the constructors of the sub classes.
     *
     * @param kid the key id.
     * @param keyType the key type.
     */
    JsonWebKey(String kid, String keyType) {
        this.kid = kid;
        this.keyType = keyType;
    }

    @Override
    public String toString() {
        return String.format("JsonWebKey[class=%s, kid=%s]", this.getClass().getSimpleName(), this.kid);
    }

    /**
     * Serializes the common JWK parameters.
     *
     * @return a JsonObject containing the shared JWK parameters.
     */
    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");

        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder()
                    .add("kty", this.keyType);
            if (Objects.nonNull(this.kid)) {
                jsonObjectBuilder.add("kid", this.kid);
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
