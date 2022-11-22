package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.websignature.Json2StringConverter;
import javax.json.JsonObject;

public interface BeforePayload {
    SignatureEnd payload(JsonObject payload);
    SignatureEnd payload(JsonObject payload, Json2StringConverter converter);
    SignatureEnd payload(String payload);
}
