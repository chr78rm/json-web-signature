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

import de.christofreichardt.json.webkey.JsonWebPublicKey;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * The first stopover within the workflow of the Fluent API regarding the validation of signatures.
 *
 * @author Christof Reichardt
 */
public interface BeforeKey {
    /**
     * Notes the given {@code PublicKey}.
     *
     * @param publicKey the given {@code PublicKey}.
     * @return the next stop within the workflow of the Fluent API regarding the validation of signatures.
     */
    ValidationEnd key(PublicKey publicKey);

    /**
     * Notes the given {@code SecretKey}.
     * @param secretKey the given {@code SecretKey}.
     * @return the next stop within the workflow of the Fluent API regarding the validation of signatures.
     */
    ValidationEnd key(SecretKey secretKey);

    /**
     * Notes the given {@link de.christofreichardt.json.webkey.JsonWebPublicKey}.
     *
     * @param jsonWebPublicKey the given {@link de.christofreichardt.json.webkey.JsonWebPublicKey}.
     * @return the next stop within the workflow of the Fluent API regarding the validation of signatures.
     */
    ValidationEnd webkey(JsonWebPublicKey jsonWebPublicKey);

    /**
     * Notes the given {@link de.christofreichardt.json.webkey.JsonWebSecretKey}.
     *
     * @param jsonWebSecretKey the given {@link de.christofreichardt.json.webkey.JsonWebSecretKey}.
     * @return the next stop within the workflow of the Fluent API regarding the validation of signatures.
     */
    ValidationEnd webkey(JsonWebSecretKey jsonWebSecretKey);
}
