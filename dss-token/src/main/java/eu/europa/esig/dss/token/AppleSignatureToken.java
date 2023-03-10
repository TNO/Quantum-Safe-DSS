/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

/**
 * Class provides an API for MacOS Keychain access.
 *
 * For more details please refer to the used documentation:
 * https://github.com/openjdk/jdk17u/blob/master/src/java.base/macosx/classes/apple/security/KeychainStore.java
 *
 */
public class AppleSignatureToken extends AbstractKeyStoreTokenConnection {

    /**
     * Default constructor
     */
    public AppleSignatureToken() {
        // empty
    }

    @Override
    protected KeyStore getKeyStore() throws DSSException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("KeychainStore");
            keyStore.load(null, null);
        } catch (IOException | GeneralSecurityException e) {
            throw new DSSException("Unable to load MacOS Keychain store", e);
        }
        return keyStore;
    }

    @Override
    protected PasswordProtection getKeyProtectionParameter() {
        return new PasswordProtection("nimp".toCharArray());
    }

    @Override
    public void close() {
        // nothing to close
    }

}
