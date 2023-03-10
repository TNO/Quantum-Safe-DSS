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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import javax.xml.bind.JAXBElement;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class DSS2258Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-PK7-2.pdf"));
	}

	@Override
	protected void checkSignatureProductionPlace(DiagnosticData diagnosticData) {
		super.checkSignatureProductionPlace(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);

		assertNotNull(signatureWrapper.getCity());
		assertNotNull(signatureWrapper.getCountryName());
		assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPostalAddress())); // wrong object type
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);

		assertNotNull(signatureWrapper.getLocation());
	}

	@SuppressWarnings("rawtypes")
	@Override
	protected void checkSignatureReports(Reports reports) {
		super.checkSignatureReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		String location = signatureWrapper.getLocation();
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertEquals(1, signatureValidationReports.size());
		
		SignatureValidationReportType signatureValidationReport = signatureValidationReports.get(0);
		SignatureAttributesType signatureAttributes = signatureValidationReport.getSignatureAttributes();
		
		boolean locationFound = false;
		for (Object signatureAttributeObj : signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()) {
			if (signatureAttributeObj instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) signatureAttributeObj;
				Object value = jaxbElement.getValue();
				if (value instanceof SASignatureProductionPlaceType) {
					SASignatureProductionPlaceType saSignatureProductionPlace = (SASignatureProductionPlaceType) value;
					List<String> addressString = saSignatureProductionPlace.getAddressString();
					assertTrue(Utils.isCollectionNotEmpty(addressString));
					assertEquals(1, addressString.size());
					assertEquals(location, addressString.get(0));
					locationFound = true;
				}
			}
		}
		assertTrue(locationFound);
	}

	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertTrue(signatureWrapper.isSigningCertificateIdentified());
		assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
		assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(SignatureLevel.PKCS7_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
