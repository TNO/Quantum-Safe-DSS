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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESManifestLevelBWithValidationTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {

		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, documents);

		documentToSign = builder.build();

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		signatureParameters.setManifestSignature(true);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));

		FileDocument fileDoc = new FileDocument("src/test/resources/sample.txt");

		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA512, fileDoc.getDigest(DigestAlgorithm.SHA512));
		digestDocument.setName(fileDoc.getName());

		documents.add(digestDocument);

		validator.setDetachedContents(documents);
		return validator;
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		int nbManifestEntries = 0;
		boolean foundManifest = false;
		boolean foundSignedProperties = false;
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			switch (xmlDigestMatcher.getType()) {
			case MANIFEST:
				foundManifest = true;
				break;
			case MANIFEST_ENTRY:
				nbManifestEntries++;
				break;
			case SIGNED_PROPERTIES:
				foundSignedProperties = true;
				break;
			default:
				break;
			}
		}

		assertTrue(foundManifest);
		assertEquals(3, nbManifestEntries);
		assertTrue(foundSignedProperties);
	}

	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
		assertNotNull(digestAlgoAndValue);
		assertNotNull(digestAlgoAndValue.getDigestMethod());
		assertNotNull(digestAlgoAndValue.getDigestValue());

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
		assertEquals(4, validationObjects.size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
