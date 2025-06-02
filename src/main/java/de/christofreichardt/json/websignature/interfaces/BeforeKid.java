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

/**
 * A stopover within the the workflow of the Fluent API regarding the generation of signatures.
 */
public interface BeforeKid extends BeforePayload {
    /**
     * Notes the given {@code kid}.
     *
     * @param kid the given {@code kid}.
     * @return the next stop within the workflow of the Fluent API regarding the generation of signatures.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4">Section 4.1.4 of RFC 7515</a>
     */
    BeforePayload kid(String kid);
}
