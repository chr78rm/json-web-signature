/*
 * Copyright (C) 2022, 2025, Christof Reichardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.christofreichardt.json.websignature;

import jakarta.json.JsonStructure;

/**
 * <p>
 * Implementations of this interface are required when formatting JSON structures in a predictable way prior to
 * applying digital signatures. Logically identical JSON structures may have different signatures dependent on
 * their formatting. RFC 7515 doesn't specify or reference a JSON canonicalization scheme although there exists
 * one (RFC 8785). This is understandable since e.g. RFC 8785 applies a "bury the head in the sand" strategy when dealing
 * with "Big Numbers", that is RFC 8785 explicitly forbids the serialization of "Big Numbers" by using the JSON number type
 * without even saying what qualifies as "Big Number". Instead those "Big Numbers" must be wrapped using JSON strings without
 * even specifying how this should be exactly done either. Needless to say that the ECMA standard 404 ("The JSON
 * Data Interchange Syntax") doesn't forbid arbitrarily big numbers as JSON numbers.
 * The internet draft "JSON Schema Validation: A Vocabulary for Structural Validation of JSON" explicitly states
 * in section 4.2 "The JSON specification allows numbers with arbitrary precision, and JSON Schema does not add any such bounds."
 * </p>
 * <p>
 * Different line endings may lead to different signatures as well.
 * </p>
 * <p>
 * The Jakarta JSON Processing reference implementation (Eclipse Parsson) does print a JSON structure without any line breaks and spaces
 * onto one line when invoking <a href="https://jakarta.ee/specifications/platform/10/apidocs/jakarta/json/jsonvalue#toString()">toString()</a>
 * but this is unspecified either. This distribution invokes indeed {@code toString()} prior to computing the signature if you don't
 * explicitly specify a converter like the {@link de.christofreichardt.json.websignature.PrettyStringConverter}.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1">Appendix A.1 of RFC 7515</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8785.html#name-dealing-with-big-numbers">Appendix D of RFC 8785</a>
 * @see <a href="https://json-schema.org/draft/2020-12/json-schema-validation.html#name-validation-of-numeric-insta">Section 4.2 of draft-bhutton-json-schema-validation-01</a>
 * @see <a href="https://www.ecma-international.org/publications-and-standards/standards/ecma-404/">ECMA-404 The JSON data interchange syntax</a>
 *
 * @author Christof Reichardt
 */
@FunctionalInterface
public interface Json2StringConverter {
    /**
     * Converts predictably the given {@code JsonStructure} into a string.
     *
     * @param jsonStructure the to be converted {@code JsonStructure}.
     * @return a string representation of the given {@code JsonStructure}.
     */
    String convert(JsonStructure jsonStructure);
}
