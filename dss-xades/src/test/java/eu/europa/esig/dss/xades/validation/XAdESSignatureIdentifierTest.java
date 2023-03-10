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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class XAdESSignatureIdentifierTest extends AbstractXAdESTestValidation {
	
	private static DSSDocument document = new FileDocument(new File("src/test/resources/validation/valid-xades.xml"));

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getPolicyId());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureDigestReference(DiagnosticData diagnosticData) {
		super.checkSignatureDigestReference(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlSignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);

		Document documentDom = DomUtils.buildDOM(document);
		NodeList nodeList = DomUtils.getNodeList(documentDom, XMLDSigPaths.SIGNATURE_PATH);
		assertEquals(1, nodeList.getLength());
		Element signatureElement = (Element) nodeList.item(0);
		byte[] canonicalizedSignatureElement = DSSXMLUtils.canonicalizeSubtree(signatureDigestReference.getCanonicalizationMethod(), signatureElement);
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), canonicalizedSignatureElement);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertNotNull(originalSignerDocuments);
		assertEquals(1, originalSignerDocuments.size());
		SignerDataWrapper xmlSignerData = originalSignerDocuments.get(0);
		assertNotNull(xmlSignerData.getId());
		
		assertEquals(1, diagnosticData.getSignatures().size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertNotNull(xmlSignatureScope.getName());
		assertNotNull(xmlSignatureScope.getDescription());
		assertNotNull(xmlSignatureScope.getScope());
		assertEquals(SignatureScopeType.PARTIAL, xmlSignatureScope.getScope());
		assertNotNull(xmlSignatureScope.getSignerData());
		assertNotNull(xmlSignatureScope.getSignerData().getId());
		assertEquals(xmlSignerData.getId(), xmlSignatureScope.getSignerData().getId());
		assertNotNull(xmlSignatureScope.getSignerData().getReferencedName());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
		assertNotNull(xmlSignatureScope.getTransformations());
		assertEquals(1, xmlSignatureScope.getTransformations().size());
	}

}
