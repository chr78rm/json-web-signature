package de.christofreichardt.json;

import java.util.Map;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

public class JsonUtils {
    public static <T extends JsonValue> T getOrElseThrow(JsonObject jsonObject, String key, Class<T> jsonType) {
        Map<Class<? extends JsonValue>, JsonValue.ValueType> types = Map.of(JsonString.class, JsonValue.ValueType.STRING);
        if (!types.containsKey(jsonType)) {
            throw new UnsupportedOperationException();
        }
        JsonValue.ValueType valueType = types.get(jsonType);
        if (!jsonObject.containsKey(key) || jsonObject.get(key).getValueType() != valueType) {
            throw new IllegalArgumentException();
        }
        @SuppressWarnings("unchecked")
        T jsonValue = (T) jsonObject.get(key);

        return jsonValue;
    }
}
