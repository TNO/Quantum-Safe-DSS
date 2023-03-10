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
package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESExtensionBToLTWithRevokedCertTest extends AbstractJAdESTestExtension {

    private JAdESSignatureParameters signatureParameters;
    private JAdESSignatureParameters extensionParameters;

    @BeforeEach
    public void init() {
        signatureParameters = super.getSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(false);

        extensionParameters = super.getExtensionParameters();
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LT;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        extensionParameters.setCheckCertificateRevocation(true);
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        JAdESService JAdESService = new JAdESService(completeCertificateVerifier);
        JAdESService.setTspSource(getUsedTSPSourceAtExtensionTime());
        return JAdESService.extendDocument(signedDocument, getExtensionParameters());
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}
