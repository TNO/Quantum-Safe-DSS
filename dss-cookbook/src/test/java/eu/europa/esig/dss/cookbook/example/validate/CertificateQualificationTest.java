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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CertificateQualificationTest {

    @Test
    public void test() {

        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/main/resources/keystore/ec.europa.eu.1.cer"));


        AIASource aiaSource = new DefaultAIASource();
        RevocationSource<OCSP> ocspSource = new OnlineOCSPSource();
        RevocationSource<CRL> crlSource = new OnlineCRLSource();

        // tag::demo[]
        // import eu.europa.esig.dss.enumerations.CertificateQualification;
        // import eu.europa.esig.dss.enumerations.CertificateType;
        // import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
        // import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
        // import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
        // import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
        // import eu.europa.esig.dss.tsl.job.TLValidationJob;
        // import eu.europa.esig.dss.tsl.source.TLSource;
        // import eu.europa.esig.dss.validation.CertificateValidator;
        // import eu.europa.esig.dss.validation.CertificateVerifier;
        // import eu.europa.esig.dss.validation.CommonCertificateVerifier;
        // import eu.europa.esig.dss.validation.reports.CertificateReports;
        // import org.apache.hc.client5.http.ssl.TrustAllStrategy;

        // Configure the internet access
        CommonsDataLoader dataLoader = new CommonsDataLoader();

        // We set an instance of TrustAllStrategy to rely on the Trusted Lists content
        // instead of the JVM trust store.
        dataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);

        // Configure the TLValidationJob to load a qualification information from the corresponding LOTL/TL
        TLValidationJob tlValidationJob = new TLValidationJob();
        tlValidationJob.setOnlineDataLoader(new FileCacheDataLoader(dataLoader));

        // Configure the relevant TrustedList
        TLSource tlSource = new TLSource();
        tlSource.setUrl("http://dss-test.lu");
        tlValidationJob.setTrustedListSources(tlSource);

        // Initialize the trusted list certificate source to fill with the information extracted from TLValidationJob
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);

        // Update TLValidationJob
        tlValidationJob.onlineRefresh();

        // Thirdly, we need to configure the CertificateVerifier
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(trustedListsCertificateSource); // configured trusted list certificate source
        cv.setAIASource(aiaSource); // configured AIA Access
        cv.setOcspSource(ocspSource); // configured OCSP Access
        cv.setCrlSource(crlSource); // configured CRL Access

        // Create an instance of CertificateValidator for the SSL Certificate with the
        // CertificateVerifier
        CertificateValidator validator = CertificateValidator.fromCertificate(certificate);
        validator.setCertificateVerifier(cv);

        // Validate the certificate
        CertificateReports reports = validator.validate();
        SimpleCertificateReport simpleReport = reports.getSimpleReport();

        // Extract the qualification information
        CertificateQualification qualificationAtCertificateIssuance = simpleReport.getQualificationAtCertificateIssuance();
        CertificateQualification qualificationAtValidationTime = simpleReport.getQualificationAtValidationTime();

        // Extract the requested information about a certificate type and its qualification
        CertificateType type = qualificationAtValidationTime.getType();
        boolean isQualifiedCertificate = qualificationAtValidationTime.isQc();
        boolean isQSCD = qualificationAtValidationTime.isQscd();

        // end::demo[]

        DetailedReport detailedReport = reports.getDetailedReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        assertNotNull(simpleReport);
        assertNotNull(detailedReport);
        assertNotNull(diagnosticData);

    }

}
