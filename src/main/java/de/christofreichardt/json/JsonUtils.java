package de.christofreichardt.json;

import java.util.Map;
import java.util.function.Supplier;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

/**
 * Provides some utility functions.
 *
 * @author Christof Reichardt
 */
public class JsonUtils {

    private JsonUtils() {
    }

    /**
     * Used to access a typed name/value pair of the given {@code JsonObject}. Either if the name/value pair doesn't exist or if the requested type of the value cannot be satisfied an
     * {@code IllegalArgumentException} will be thrown. At present only JsonString values can be requested.
     *
     * @param jsonObject the object to be worked with
     * @param key the key whose associated value we are interested in
     * @param jsonType the desired class of the {@code JsonValue}
     * @return the associated value
     * @param <T> the type of the {@code JsonValue}
     */
    public static <T extends JsonValue> T orElseThrow(JsonObject jsonObject, String key, Class<T> jsonType) {
        return orElseThrow(jsonObject, key, jsonType, () -> new IllegalArgumentException());
    }

    static <T extends JsonValue, X extends RuntimeException> T orElseThrow(JsonObject jsonObject, String key, Class<T> jsonType, Supplier<? extends X> exceptionSupplier) {
        Map<Class<? extends JsonValue>, JsonValue.ValueType> types = Map.of(JsonString.class, JsonValue.ValueType.STRING);
        if (!types.containsKey(jsonType)) {
            throw new UnsupportedOperationException();
        }
        JsonValue.ValueType valueType = types.get(jsonType);
        if (!jsonObject.containsKey(key) || jsonObject.get(key).getValueType() != valueType) {
            throw exceptionSupplier.get();
        }
        @SuppressWarnings("unchecked")
        T jsonValue = (T) jsonObject.get(key);

        return jsonValue;
    }
}
