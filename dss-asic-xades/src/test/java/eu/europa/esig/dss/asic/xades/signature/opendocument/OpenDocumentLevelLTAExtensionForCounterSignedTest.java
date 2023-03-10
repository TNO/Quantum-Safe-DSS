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
package eu.europa.esig.dss.asic.xades.signature.opendocument;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.AbstractASiCWithXAdESTestValidation;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenDocumentLevelLTAExtensionForCounterSignedTest extends AbstractASiCWithXAdESTestValidation {

	private DSSDocument documentToSign;
	private ASiCWithXAdESService service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private XAdESCounterSignatureParameters counterSignatureParameters;
	
	private String signingAlias;
	
	private static Stream<Arguments> data() {
		File folder = new File("src/test/resources/opendocument");
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "odt", "ods", "odp", "odg" }, true);
		

		List<Arguments> args = new ArrayList<>();
		for (File file : listFiles) {
			args.add(Arguments.of(new FileDocument(file)));
		}
		return args.stream();
	}

	@BeforeEach
	public void init() throws Exception {
		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		signingAlias = SELF_SIGNED_USER;
		
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		signingAlias = GOOD_USER;
		
		counterSignatureParameters = new XAdESCounterSignatureParameters();
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
	}
	
	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void test(DSSDocument fileToTest) {
		documentToSign = fileToTest;
		
		signingAlias = SELF_SIGNED_USER;
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		signingAlias = GOOD_USER;

		SignedDocumentValidator validator = getValidator(signedDocument);
		String mainSignatureId = validator.getSignatures().get(0).getId();
		
		counterSignatureParameters.setSignatureIdToCounterSign(validator.getSignatures().get(0).getId());
		
		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument counterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);
		
		validator = getValidator(counterSignedSignature);
		assertEquals(1, validator.getSignatures().size());
		assertEquals(mainSignatureId, validator.getSignatures().get(0).getId());
		assertEquals(1, validator.getSignatures().get(0).getCounterSignatures().size());
		
		String counterSignatureId = validator.getSignatures().get(0).getCounterSignatures().get(0).getId();
		assertNotEquals(mainSignatureId, counterSignatureId);
		
		// counterSignedSignature.save("target/counterSignedSignature.xml");
		
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		DSSDocument ltaXAdES = service.extendDocument(counterSignedSignature, signatureParameters);
		
		// ltaXAdES.save("target/ltaXAdES.xml");
		
		Reports reports = verify(ltaXAdES);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(mainSignatureId);
		assertNotNull(signatureWrapper);
		assertFalse(signatureWrapper.isCounterSignature());
		assertEquals(SignatureLevel.XAdES_BASELINE_LTA, signatureWrapper.getSignatureFormat());
		
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignaturesForMasterSignature(signatureWrapper);
		assertEquals(1, counterSignatures.size());
		
		SignatureWrapper counterSignature = counterSignatures.iterator().next();
		assertEquals(counterSignatureId, counterSignature.getId());
		assertEquals(SignatureLevel.XAdES_BASELINE_B, counterSignature.getSignatureFormat());
		
		// impossible to counter sign an extended signature
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSignatureIdToCounterSign(counterSignatureId);
		Exception exception = assertThrows(IllegalInputException.class, () -> service.getDataToBeCounterSigned(ltaXAdES, counterSignatureParameters));
		assertEquals(String.format("Unable to counter sign a signature with Id '%s'. "
				+ "The signature is timestamped by a master signature!", counterSignature.getId()), exception.getMessage());
		
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		List<String> certificateValuesIds = foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)
				.stream().map(c -> c.getId()).collect(Collectors.toList());
		for (CertificateWrapper certificateWrapper : counterSignature.getCertificateChain()) {
			assertTrue(certificateValuesIds.contains(certificateWrapper.getId()));
		}
		
		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES)));
		
		assertTrue(counterSignature.getSigningCertificate().isRevocationDataAvailable());
		
		// possible to counter sign the main signature again
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		dataToBeCounterSigned = service.getDataToBeCounterSigned(ltaXAdES, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		counterSignedSignature = service.counterSignSignature(ltaXAdES, counterSignatureParameters, signatureValue);
		assertNotNull(counterSignedSignature);
		
		validator = getValidator(counterSignedSignature);
		assertEquals(1, validator.getSignatures().size());
		
		AdvancedSignature mainSignature = validator.getSignatures().get(0);
		assertEquals(mainSignatureId, mainSignature.getId());
		
		assertEquals(2, mainSignature.getCounterSignatures().size());
		assertEquals(counterSignatureId, mainSignature.getCounterSignatures().get(0).getId());
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		
		AdvancedSignature advancedSignature = signatures.get(0);
		List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(2, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isCounterSignature());
		
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignatures();
		assertTrue(Utils.isCollectionNotEmpty(counterSignatures));
		SignatureWrapper counterSignature = counterSignatures.iterator().next();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertFalse(timestampWrapper.getTimestampedSignatures().stream().map(s -> s.getId()).collect(Collectors.toList())
						.contains(counterSignature.getId()));
				assertFalse(timestampWrapper.getTimestampedCertificates().stream().map(c -> c.getId()).collect(Collectors.toList())
						.contains(counterSignature.getSigningCertificate().getId()));
				sigTstFound = true;
				
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
				assertTrue(timestampWrapper.getTimestampedSignatures().stream().map(s -> s.getId()).collect(Collectors.toList())
						.contains(counterSignature.getId()));
				assertTrue(timestampWrapper.getTimestampedCertificates().stream().map(c -> c.getId()).collect(Collectors.toList())
						.contains(counterSignature.getSigningCertificate().getId()));
				arcTstFound = true;
				
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}
	
	public void verifySignatureFileName(List<DSSDocument> signatureFiles) {
		assertEquals(1, signatureFiles.size());
		DSSDocument signature = signatureFiles.get(0);
		assertEquals("META-INF/documentsignatures.xml", signature.getName());
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
			if (diagnosticData.isBLevelTechnicallyValid(signatureId) && !signatureWrapper.isCounterSignature()) {
				List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
				assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
				for (DSSDocument document : retrievedOriginalDocuments) {
					assertNotNull(document);
				}
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return documentToSign;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

}
