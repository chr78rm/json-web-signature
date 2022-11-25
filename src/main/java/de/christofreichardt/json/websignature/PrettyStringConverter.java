package de.christofreichardt.json.websignature;

import java.io.StringWriter;
import java.util.Map;
import jakarta.json.Json;
import jakarta.json.JsonStructure;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

/**
 *
 * @author Christof Reichardt
 */
public class PrettyStringConverter implements Json2StringConverter {

    @Override
    public String convert(JsonStructure jsonStructure) {
        JsonWriterFactory jsonWriterFactory = Json.createWriterFactory(Map.of(JsonGenerator.PRETTY_PRINTING, Boolean.TRUE));
        StringWriter stringWriter = new StringWriter();
        try ( JsonWriter jsonWriter = jsonWriterFactory.createWriter(stringWriter)) {
            jsonWriter.write(jsonStructure);
        }
        return stringWriter.toString();
    }
}
