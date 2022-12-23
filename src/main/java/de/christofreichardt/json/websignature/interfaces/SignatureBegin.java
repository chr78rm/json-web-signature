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

import de.christofreichardt.json.webkey.JsonWebKeyPair;
import de.christofreichardt.json.webkey.JsonWebSecretKey;
import java.security.KeyPair;
import javax.crypto.SecretKey;

/**
 * Defines the starting point for generating JSON Web Signatures.
 *
 * @author Christof Reichardt
 */
public interface SignatureBegin {
    /**
     * Notes the given {@link de.christofreichardt.json.webkey.JsonWebKeyPair}. The private part will be used for generating the actual signature. The public part will be
     * exposed within the JOSE header if you don't chose to explicitly hand over a JOSE header yourself within the next step.
     *
     * @param jsonWebKeyPair the given {@link de.christofreichardt.json.webkey.JsonWebKeyPair}.
     * @return the next stop within the workflow of the Fluent API regarding the generation of signatures.
     */
    BeforeHeader webkey(JsonWebKeyPair jsonWebKeyPair);

    /**
     * Notes the given {@link de.christofreichardt.json.webkey.JsonWebSecretKey}. The wrapped secret key will be used for generating the signature.
     *
     * @param jsonWebSecretKey the given {@link de.christofreichardt.json.webkey.JsonWebSecretKey}.
     * @return the next stop within the workflow of the Fluent API regarding the generation of signatures.
     */
    BeforeHeader webkey(JsonWebSecretKey jsonWebSecretKey);

    /**
     * The given {@code KeyPair} will be used to build a {@link de.christofreichardt.json.webkey.JsonWebKeyPair}. The private part will be used for generating the
     * actual signature. The public part will be exposed within the JOSE header if you don't chose to explicitly hand over a JOSE header yourself within the next step.
     *
     * @param keyPair the given {@code KeyPair}.
     * @return the next stop within the workflow of the Fluent API regarding the generation of signatures.
     */
    BeforeHeader key(KeyPair keyPair);

    /**
     * The given {@code SecretKey} will be used to build a {@link de.christofreichardt.json.webkey.JsonWebSecretKey}.
     * @param secretKey the given {@code SecretKey}.
     * @return the next stop within the workflow of the Fluent API regarding the generation of signatures.
     */
    BeforeHeader key(SecretKey secretKey);
}
