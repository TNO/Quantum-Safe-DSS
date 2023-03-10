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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESDoubleLTATest extends AbstractJAdESTestValidation {
	
	@Test
	public void test() throws IOException {
		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.json");

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        JAdESService service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        // signedDocument.save("target/signed.json");
         
        checkOnSigned(signedDocument, 0);

        service.setTspSource(getGoodTsaCrossCertification());

        JAdESSignatureParameters extendParameters = new JAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extendParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);
        
        checkOnSigned(extendedDocument, 1);
        
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);
        
        // doubleLTADoc.save("target/doubleLTA.json");
         
        checkOnSigned(doubleLTADoc, 2);
        
        Reports reports = verify(doubleLTADoc);
        
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        
        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        
		assertEquals(3, diagnosticData.getTimestampList().size());
		TimestampWrapper signatureTst = diagnosticData.getTimestampList().get(0);
		TimestampWrapper firstArchiveTst = diagnosticData.getTimestampList().get(1);
		TimestampWrapper secondArchiveTst = diagnosticData.getTimestampList().get(2);
        
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<RelatedCertificateWrapper> timestampValidationDataCertificates = signature.foundCertificates()
				.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
        assertTrue(Utils.isCollectionNotEmpty(timestampValidationDataCertificates));

		List<TimestampWrapper> timestampedTimestamps = secondArchiveTst.getTimestampedTimestamps();
		assertEquals(2, timestampedTimestamps.size());
		assertEquals(signatureTst.getId(), timestampedTimestamps.get(0).getId());
		assertEquals(firstArchiveTst.getId(), timestampedTimestamps.get(1).getId());
        
		List<CertificateWrapper> timestampedCertificates = secondArchiveTst.getTimestampedCertificates();
        List<String> timestampedCertIds = timestampedCertificates.stream().map(CertificateWrapper::getId).collect(Collectors.toList());
		for (CertificateWrapper certificateWrapper : signature.foundCertificates().getRelatedCertificates()) {
			assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
		}
		for (CertificateWrapper certificateWrapper : signatureTst.foundCertificates().getRelatedCertificates()) {
			assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
		}
		for (CertificateWrapper certificateWrapper : firstArchiveTst.foundCertificates().getRelatedCertificates()) {
        	assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }
        
		assertEquals(0, firstArchiveTst.foundRevocations().getRelatedRevocationData().size());
        List<RelatedRevocationWrapper> timestampValidationDataRevocations = signature
				.foundRevocations().getRelatedRevocationData();
		assertTrue(Utils.isCollectionNotEmpty(timestampValidationDataRevocations));
        
		List<RevocationWrapper> timestampedRevocations = secondArchiveTst.getTimestampedRevocations();
        assertEquals(timestampValidationDataRevocations.size(), timestampedRevocations.size());
        
        List<String> timestampedRevocationIds = timestampedRevocations.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
        for (RevocationWrapper revocationWrapper : timestampValidationDataRevocations) {
        	assertTrue(timestampedRevocationIds.contains(revocationWrapper.getId()));
        }
        
        assertContainsAllRevocationData(signature.getCertificateChain());
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
        	assertContainsAllRevocationData(timestamp.getCertificateChain());
        }
        for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
        	assertContainsAllRevocationData(revocation.getCertificateChain());
        }
        
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
		return validator;
	}
	
	@SuppressWarnings("unchecked")
	private void checkOnSigned(DSSDocument document, int expectedArcTsts) {
		assertTrue(DSSJsonUtils.isJsonDocument(document));
		try {
			byte[] binaries = DSSUtils.toByteArray(document);
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(binaries));
			
			String firstEntryName = rootStructure.keySet().iterator().next();
			assertEquals(JWSConstants.PAYLOAD, firstEntryName);
			
			String payload = (String) rootStructure.get(firstEntryName);
			assertNotNull(payload);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));
			
			String header = (String) rootStructure.get("protected");
			assertNotNull(header);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(header)));
			
			String signatureValue = (String) rootStructure.get("signature");
			assertNotNull(signatureValue);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValue)));
			
			Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get("header");
			assertTrue(Utils.isMapNotEmpty(unprotected));
			
			List<Object> unsignedProperties = (List<Object>) unprotected.get("etsiU");
			
			int xValsCounter = 0;
			int rValsCounter = 0;
			int arcTstCounter = 0;
			int tstVdCounter = 0;
			
			for (Object property : unsignedProperties) {
				Map<String, Object> map = DSSJsonUtils.parseEtsiUComponent(property);

				List<?> xVals = (List<?>) map.get("xVals");
				if (xVals != null) {
					++xValsCounter;
				}
				Map<?, ?> rVals = (Map<?, ?>) map.get("rVals");
				if (rVals != null) {
					++rValsCounter;
				}
				Map<?, ?> arcTst = (Map<?, ?>) map.get("arcTst");
				if (arcTst != null) {
					++arcTstCounter;
					List<?> tsTokens = (List<?>) arcTst.get("tstTokens");
					assertEquals(1, tsTokens.size());
				}
				Map<?, ?> tstVd = (Map<?, ?>) map.get("tstVD");
				if (tstVd != null) {
					++tstVdCounter;
				}
			}

			assertEquals(1, xValsCounter);
			assertEquals(1, rValsCounter);
			assertEquals(expectedArcTsts, arcTstCounter);
			assertEquals(expectedArcTsts > 0 ? expectedArcTsts - 1 : 0, tstVdCounter);

		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
	}
	
	private void assertContainsAllRevocationData(List<CertificateWrapper> certificateChain) {
        for (CertificateWrapper certificate : certificateChain) {
        	if (certificate.isTrusted()) {
        		break;
        	}
        	assertTrue(certificate.isRevocationDataAvailable() || certificate.isSelfSigned(), 
        			"Certificate with id : [" + certificate.getId() + "] does not have a revocation data!");
        }
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}

}
