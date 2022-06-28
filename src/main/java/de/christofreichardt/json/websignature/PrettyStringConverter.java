package de.christofreichardt.json.websignature;

import java.io.StringWriter;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonStructure;
import javax.json.JsonWriter;
import javax.json.JsonWriterFactory;
import javax.json.stream.JsonGenerator;

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
