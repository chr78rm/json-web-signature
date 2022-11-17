package de.christofreichardt.json.websignature.interfaces;

import javax.json.JsonObject;

public interface BeforePayload {
    SignatureEnd payload(JsonObject payload);
}
