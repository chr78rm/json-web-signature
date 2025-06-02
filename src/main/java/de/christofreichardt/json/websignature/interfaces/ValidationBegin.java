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

package de.christofreichardt.json.websignature.interfaces;

import de.christofreichardt.json.websignature.JWSCompactSerialization;

/**
 * The first stopover within the workflow of the Fluent API regarding the validation of signatures.
 *
 * @author Christof Reichardt
 */
public interface ValidationBegin {
    /**
     * Notes the given {@link de.christofreichardt.json.websignature.JWSCompactSerialization}.
     *
     * @param compactSerialization the given {@link de.christofreichardt.json.websignature.JWSCompactSerialization}.
     * @return the next stop within the workflow of the Fluent API regarding the validation of signatures.
     */
    BeforeKey compactSerialization(JWSCompactSerialization compactSerialization);
}
