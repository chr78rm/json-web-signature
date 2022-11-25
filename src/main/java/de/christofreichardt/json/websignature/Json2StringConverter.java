package de.christofreichardt.json.websignature;

import jakarta.json.JsonStructure;

/**
 *
 * @author Christof Reichardt
 */
@FunctionalInterface
public interface Json2StringConverter {
    String convert(JsonStructure jsonStructure);
}
