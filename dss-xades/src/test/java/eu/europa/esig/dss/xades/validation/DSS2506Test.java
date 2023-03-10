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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DSS2506Test extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss-2506.xml");
    }

    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // orphan data must not be added into the signature
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences())); // orphan signing cert
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().iterator().next();
        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        assertTrue(Utils.isCollectionNotEmpty(digestMatchers));

        assertFalse(signatureWrapper.isSignatureIntact());
        assertFalse(signatureWrapper.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
    }

    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().iterator().next();
        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
        assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());

        assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates().getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

        List<CertificateRefWrapper> orphanSigningCertificates = signatureWrapper.foundCertificates().getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertTrue(Utils.isCollectionNotEmpty(orphanSigningCertificates));
        assertEquals(1, orphanSigningCertificates.size());

        CertificateRefWrapper orphan = orphanSigningCertificates.iterator().next();
        assertNotNull(orphan.getDigestAlgoAndValue());
        assertTrue(orphan.isIssuerSerialPresent());
        assertFalse(orphan.isIssuerSerialMatch());
    }

    protected void validateSignerInformation(SignerInformationType signerInformation) {
        assertNull(signerInformation);
    }

}
