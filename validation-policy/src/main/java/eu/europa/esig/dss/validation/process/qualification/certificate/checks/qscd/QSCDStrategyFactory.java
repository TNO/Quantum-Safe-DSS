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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;

/**
 * Used to obtain a {@code QSCDStrategy} for the given certificate and a TrustedService
 *
 */
public final class QSCDStrategyFactory {

	/**
	 * Empty constructor
	 */
	private QSCDStrategyFactory() {
	}

	/**
	 * Creates a QSCD Strategy from the given certificate
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @return {@link QSCDStrategy}
	 */
	public static QSCDStrategy createQSCDFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new QSCDByCertificatePostEIDAS(signingCertificate);
		} else {
			return new QSCDByCertificatePreEIDAS(signingCertificate);
		}
	}

	/**
	 * Creates a QSCD Strategy from the TrustedService
	 *
	 * @param trustedService {@link TrustedServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus}
	 * @param qscdFromCertificate {@link QSCDStrategy}
	 * @return {@link QSCDStrategy}
	 */
	public static QSCDStrategy createQSCDFromTL(TrustedServiceWrapper trustedService,
												CertificateQualifiedStatus qualified, QSCDStrategy qscdFromCertificate) {
		return new QSCDByTL(trustedService, qualified, qscdFromCertificate);
	}

	/**
	 * Creates a QSCD Strategy from the given certificate and TrustedService
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @param caQcTrustedService {@link TrustedServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus} of the certificate
	 * @return {@link QSCDStrategy}
	 */
	public static QSCDStrategy createQSCDFromCertAndTL(CertificateWrapper signingCertificate,
					TrustedServiceWrapper caQcTrustedService, CertificateQualifiedStatus qualified) {
		QSCDStrategy qscdFromCert = createQSCDFromCert(signingCertificate);
		return createQSCDFromTL(caQcTrustedService, qualified, qscdFromCert);
	}

}
