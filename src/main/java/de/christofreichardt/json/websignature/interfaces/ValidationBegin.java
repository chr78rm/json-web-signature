package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.websignature.JWSCompactSerialization;

public interface ValidationBegin {
    BeforeKey compactSerialization(JWSCompactSerialization compactSerialization);
}
