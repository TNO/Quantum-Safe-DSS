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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBCounterSignedWithUserFriendlyIdentifierProviderTest extends AbstractXAdESCounterSignatureTest {

    private XAdESService service;
    private DSSDocument documentToSign;

    private Date signingDate;

    @BeforeEach
    public void init() throws Exception {
        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        signingDate = new Date();
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected TokenIdentifierProvider getTokenIdentifierProvider() {
        return new UserFriendlyIdentifierProvider();
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

        UserFriendlyIdentifierProvider userFriendlyIdentifierProvider = new UserFriendlyIdentifierProvider();
        assertEquals(1, advancedSignatures.size());

        AdvancedSignature advancedSignature = advancedSignatures.get(0);
        SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
        assertNull(signature);

        signature = diagnosticData.getSignatureById(userFriendlyIdentifierProvider.getIdAsString(advancedSignature));
        assertNotNull(signature);

        assertTrue(signature.getId().contains("SIGNATURE"));
        assertFalse(signature.getId().contains("COUNTER-SIGNATURE"));
        assertTrue(signature.getId().contains(signature.getSigningCertificate().getCommonName()));
        assertTrue(signature.getId().contains(
                DSSUtils.formatDateWithCustomFormat(signature.getClaimedSigningTime(), "yyyyMMdd-HHmm")));

        List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
        assertEquals(1, counterSignatures.size());

        AdvancedSignature counterSignature = counterSignatures.get(0);
        SignatureWrapper counterSignatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());
        assertNull(counterSignatureWrapper);

        counterSignatureWrapper = diagnosticData.getSignatureById(userFriendlyIdentifierProvider.getIdAsString(counterSignature));
        assertNotNull(counterSignatureWrapper);

        assertTrue(counterSignatureWrapper.getId().contains("COUNTER-SIGNATURE"));
        assertTrue(counterSignatureWrapper.getId().contains(counterSignatureWrapper.getSigningCertificate().getCommonName()));
        assertTrue(counterSignatureWrapper.getId().contains(
                DSSUtils.formatDateWithCustomFormat(counterSignatureWrapper.getClaimedSigningTime(), "yyyyMMdd-HHmm")));

        assertNotEquals(signature.getId(), counterSignatureWrapper.getId());

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getUsedCertificates()));
        for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
            assertTrue(certificateWrapper.getId().contains("CERTIFICATE"));
            assertTrue(certificateWrapper.getId().contains(certificateWrapper.getCommonName()));
            assertTrue(certificateWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(certificateWrapper.getNotBefore(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getOriginalSignerDocuments()));
        for (SignerDataWrapper signerDataWrapper: diagnosticData.getOriginalSignerDocuments()) {
            assertTrue(signerDataWrapper.getId().contains("DOCUMENT"));
            assertTrue(signerDataWrapper.getId().contains(
                    DSSUtils.replaceAllNonAlphanumericCharacters(signerDataWrapper.getReferencedName(), "-")));
        }
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}