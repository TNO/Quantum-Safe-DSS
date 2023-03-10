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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceTypeIdentifier;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class UniqueServiceFilterTest {

	private final static Date BEFORE_EIDAS_DATE = DatatypeConverter.parseDateTime("2014-07-01T00:00:00-00:00").getTime();
	private final static Date AFTER_EIDAS_DATE = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

	@Test
	public void testCanConcludeOneTrustService() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionNotEmpty(filtered));
	}

	@Test
	public void testCanConclude() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.GRANTED);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionNotEmpty(filtered));
	}

	@Test
	public void testCannotConcludeServiceDateConflict() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(BEFORE_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.GRANTED);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}

	@Test
	public void testCannotConcludeTypeConflict() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setServiceNames(Arrays.asList("Test"));
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.GRANTED);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESEAL.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}
	
	@Test
	public void testCannotConcludeConflictWithdrawn() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setServiceNames(Arrays.asList("Test"));
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.WITHDRAWN);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}

	@Test
	public void testCannotConcludeConflictQSCD() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setServiceNames(Arrays.asList("Test"));
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.GRANTED);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_NO_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}

	@Test
	public void testCannotConcludeConflictQualified() {

		CertificateWrapper emptyCert = getCertificate(AFTER_EIDAS_DATE);

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setServiceNames(Arrays.asList("Test"));
		ts0.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts0.setStatus(TrustedServiceStatus.GRANTED);
		ts0.setStartDate(AFTER_EIDAS_DATE);
		ts0.setCapturedQualifiers(Arrays.asList(
				ServiceQualification.QC_STATEMENT.getUri(), ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setServiceNames(Arrays.asList("Test"));
		ts1.setType(ServiceTypeIdentifier.CA_QC.getUri());
		ts1.setStatus(TrustedServiceStatus.GRANTED);
		ts1.setStartDate(AFTER_EIDAS_DATE);
		ts1.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}

	private CertificateWrapper getCertificate(Date notBefore) {
		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setNotBefore(notBefore);
		xmlCertificate.getCertificateExtensions().add(new XmlCertificatePolicies());
		return new CertificateWrapper(xmlCertificate);
	}

}
