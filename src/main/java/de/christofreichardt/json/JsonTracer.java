/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.json;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import jakarta.json.Json;
import jakarta.json.JsonStructure;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

/**
 *
 * @author CReichardt
 */
abstract public class JsonTracer implements Traceable {

    private final JsonWriterFactory jsonWriterFactory;

    public JsonTracer() {
        Map<String, Object> writerProps = new HashMap<>();
        writerProps.put(JsonGenerator.PRETTY_PRINTING, Boolean.TRUE);
        this.jsonWriterFactory = Json.createWriterFactory(writerProps);
    }

    public void trace(JsonStructure jsonStructure) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "trace(JsonStructure jsonStructure)");

        try {
            try {
                byte[] bytes;
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                try (JsonWriter jsonWriter = this.jsonWriterFactory.createWriter(byteArrayOutputStream, Charset.forName("UTF-8"));) {
                    jsonWriter.write(jsonStructure);
                }
                tracer.out().println();
                bytes = byteArrayOutputStream.toByteArray();
                try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
                        InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream, Charset.forName("UTF-8"));
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
                    bufferedReader.lines().forEach(line -> tracer.out().printfIndentln(line));
                }
                tracer.out().println();
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        } finally {
            tracer.wayout();
        }
    }

}
