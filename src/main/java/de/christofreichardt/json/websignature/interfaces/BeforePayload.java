/*
 * Copyright (C) 2022, Christof Reichardt
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

package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.websignature.Json2StringConverter;
import jakarta.json.JsonObject;

/**
 * A stopover within the the workflow of the Fluent API regarding the generation of signatures.
 */
public interface BeforePayload {
    /**
     * Introduces the actual payload.
     *
     * @param payload the given payload
     * @return the last step within the workflow of the Fluent API regarding the generation of signatures.
     */
    SignatureEnd payload(JsonObject payload);

    /**
     * Introduces the actual payload together with a {@link de.christofreichardt.json.websignature.Json2StringConverter}.
     *
     * @param payload the given payload.
     * @param converter the desired converter.
     * @return the last step within the workflow of the Fluent API regarding the generation of signatures.
     */
    SignatureEnd payload(JsonObject payload, Json2StringConverter converter);

    /**
     * Introduces the actual payload as string. The string must be valid JSON at present.
     *
     * @param payload the given payload.
     * @return the last step within the workflow of the Fluent API regarding the generation of signatures.
     */
    SignatureEnd payload(String payload);
}
