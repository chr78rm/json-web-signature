package de.christofreichardt.json.websignature.interfaces;

public interface BeforeHeader extends BeforeKid {
    BeforeKid typ(String typ);
    BeforePayload header(String strHeader);
}
