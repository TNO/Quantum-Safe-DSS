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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import org.junit.jupiter.api.Test;

// import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DilithiumTest {

    static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    @Test
    public void dil2() throws GeneralSecurityException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DILITHIUM2", DSSSecurityProvider.getSecurityProviderName());
    KeyPair kp = kpg.generateKeyPair();
    assertNotNull(kp);

    PublicKey publicKey = kp.getPublic();
    assertNotNull(publicKey);
    assertEquals("DILITHIUM2", publicKey.getAlgorithm());
    assertEquals(EncryptionAlgorithm.DILITHIUM2, EncryptionAlgorithm.forKey(publicKey));

    PrivateKey privateKey = kp.getPrivate();
    assertNotNull(privateKey);
    assertEquals("DILITHIUM2", privateKey.getAlgorithm());
    }
}