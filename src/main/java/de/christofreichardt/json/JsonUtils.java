package de.christofreichardt.json;

import java.util.Map;
import java.util.function.Supplier;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

public class JsonUtils {

    public static <T extends JsonValue> T orElseThrow(JsonObject jsonObject, String key, Class<T> jsonType) {
        return orElseThrow(jsonObject, key, jsonType, () -> new IllegalArgumentException());
    }

    public static <T extends JsonValue, X extends RuntimeException> T orElseThrow(JsonObject jsonObject, String key, Class<T> jsonType, Supplier<? extends X> exceptionSupplier) {
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
