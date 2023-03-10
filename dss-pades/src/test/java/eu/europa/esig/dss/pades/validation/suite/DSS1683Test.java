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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DSS1683Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-1683.pdf"));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		
		XmlDigestMatcher xmlDigestMatcher = signature.getDigestMatchers().get(0);
		assertEquals(DigestMatcherType.CONTENT_DIGEST, xmlDigestMatcher.getType());
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		XmlBasicBuildingBlocks signatureBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBasicBuildingBlock.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureById.isSigningCertificateIdentified());
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		AdvancedSignature firstSig = signatures.get(0);

		// Signature has been generated in the very first version of the PDF
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(firstSig.getId());
		assertEquals(0, originalDocuments.size());
	}
	
	@Test
	public void test() {
		// the extracted Contents
		String base64cms = "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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
		byte[] fromBase64 = Utils.fromBase64(base64cms);
		InMemoryDocument document = new InMemoryDocument(fromBase64);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		assertFalse(signatureWrapper.isSignatureIntact());
		assertFalse(signatureWrapper.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
		assertEquals(DigestMatcherType.CONTENT_DIGEST, xmlDigestMatcher.getType());
		assertFalse(xmlDigestMatcher.isDataFound());
		assertFalse(xmlDigestMatcher.isDataIntact());
	}

}
