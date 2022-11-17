package de.christofreichardt.json.websignature.interfaces;

public interface BeforeKid extends BeforePayload {
    BeforePayload kid(String kid);
}
