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

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.TimeZone;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.xml.security.signature.Reference;
import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;

public class XAdESLevelLTAXPath2FilterEnvelopingWithContentTstTest extends AbstractXAdESTestSignature {
	
	private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm";

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/sample-c14n-dss.xml");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setEmbedXML(true);
		
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		Date date = sdf.parse("2020-08-01 12:00");

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsaByTime(date));
		
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(documentToSign);
		dssReference.setId("Canonicalization-Ref-Test");
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		dssReference.setUri("#document");
		dssReference.setType(Reference.OBJECT_URI);
		dssReference.setTransforms(Arrays.asList(new XPath2FilterTransform("//*[@Id='dss1']", "intersect")));
		
		signatureParameters.setReferences(Arrays.asList(dssReference));
		signatureParameters.setContentTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, CanonicalizationMethod.EXCLUSIVE));
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
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
