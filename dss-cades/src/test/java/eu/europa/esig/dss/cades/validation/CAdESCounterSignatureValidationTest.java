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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.InputStream;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CAdESCounterSignatureValidationTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		FileDocument fileDocument = new FileDocument("src/test/resources/validation/counterSig.p7m");
		
		try (InputStream is = fileDocument.openStream()) {
			CMSSignedData cms = new CMSSignedData(is);
			Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
			assertEquals(1, signers.size());

			Store<X509CertificateHolder> certificates = cms.getCertificates();

			SignerInformation signerInformation = signers.iterator().next();

			Collection<X509CertificateHolder> matches = certificates.getMatches(signerInformation.getSID());
			X509CertificateHolder cert = matches.iterator().next();

			SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert);

			assertTrue(signerInformation.verify(verifier));

			SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
			for (SignerInformation counterSigner : counterSignatures) {

				Collection<X509CertificateHolder> matchesCounter = certificates.getMatches(counterSigner.getSID());
				X509CertificateHolder counterCert = matchesCounter.iterator().next();

				SignerInformationVerifier counterVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(counterCert);

				assertTrue(counterSigner.verify(counterVerifier));
			}
		} catch (Exception e) {
			fail(e);
		}
		
		return fileDocument;
		
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		assertNull(diagnosticData.getSignatureDate(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		// signing-time is absent
		assertEquals(SignatureLevel.CAdES_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
