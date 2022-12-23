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

import de.christofreichardt.json.websignature.JWSCompactSerialization;
import java.security.GeneralSecurityException;

/**
 * Defines the final step within the workflow of the Fluent API regarding the generation of signatures.
 */
public interface SignatureEnd {
    /**
     * Uses the gathered information to create a JSON Web Signature using the JWS Compact Serialization.
     *
     * @return a {@link de.christofreichardt.json.websignature.JWSCompactSerialization}.
     * @throws GeneralSecurityException passed through from the underlying implementations of the algorithms by the JDK.
     */
    JWSCompactSerialization sign() throws GeneralSecurityException;
}
