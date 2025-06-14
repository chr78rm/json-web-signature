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

import java.security.GeneralSecurityException;

/**
 * Defines the final step within the workflow of the Fluent API regarding the generation of signatures.
 *
 * @author Christof Reichardt
 */
public interface ValidationEnd {
    /**
     * Uses the gathered information to validate the signature.
     *
     * @return true if the signature was verified.
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    boolean validate() throws GeneralSecurityException;
}
