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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.validation.RevocationDataVerifier;
import org.slf4j.event.Level;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CertificateVerifierSnippet {

	public static void main(String[] args) throws Exception {

		AIASource aiaSource = null;
		CertificateSource adjunctCertSource = null;
		CertificateSource trustedCertSource = null;
		CRLSource crlSource = null;
		OCSPSource ocspSource = null;

		// tag::demo[]
		// import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
		// import eu.europa.esig.dss.alert.LogOnStatusAlert;
		// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
		// import eu.europa.esig.dss.validation.CertificateVerifier;
		// import eu.europa.esig.dss.validation.CommonCertificateVerifier;
		// import eu.europa.esig.dss.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
		// import eu.europa.esig.dss.validation.RevocationDataVerifier;
		// import org.slf4j.event.Level;
		// import java.util.Arrays;

		CertificateVerifier cv = new CommonCertificateVerifier();

		// tag::trusted-cert-source[]
		// The trusted certificate source is used to provide trusted certificates
		// (the trust anchors where the certificate chain building should stop)
		cv.setTrustedCertSources(trustedCertSource);
		// end::trusted-cert-source[]

		// tag::adjunct-cert-source[]
		// The adjunct certificate source is used to provide missing intermediate certificates
		// (not trusted certificates)
		cv.setAdjunctCertSources(adjunctCertSource);
		// end::adjunct-cert-source[]

		// The AIA source is used to collect certificates from external resources (AIA)
		cv.setAIASource(aiaSource);

		// The OCSP Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setOcspSource(ocspSource);

		// The CRL Source to be used for external accesses (can be configured with a
		// cache,...)
		cv.setCrlSource(crlSource);
		
		// Sets the default digest algorithm that will be used for digest calculation
		// of tokens used during the validation process. 
		// The values will be used in validation reports.
		// Default : DigestAlgorithm.SHA256
		cv.setDefaultDigestAlgorithm(DigestAlgorithm.SHA512);

		// Define the behavior to be followed by DSS in case of revocation checking for
		// certificates issued from an unsure source (DSS v5.4+)
		// Default : revocation check is disabled for unsure sources (security reasons)
		cv.setCheckRevocationForUntrustedChains(false);

		// DSS v5.4+ : The 3 below configurations concern the extension mode (LT/LTA
		// extension)

		// Defines a behavior in case of missing revocation data
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

		// Defines a behavior if a TSU certificate chain is not covered with a
		// revocation data (timestamp generation time > CRL/OCSP production time).
		// Default : LogOnStatusAlert -> a WARN log
		cv.setAlertOnUncoveredPOE(new LogOnStatusAlert(Level.WARN));

		// Defines a behavior if a revoked certificate is present
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());

		// Defines a behavior if an invalid timestamp is found
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());
		
		// DSS v5.5+ : defines a behavior in case if there is no valid revocation
		// data with thisUpdate time after the best signature time
		// Example: if a signature was extended to T level then the obtained revocation 
		// must have thisUpdate time after production time of the signature timestamp.
		// Default : LogOnStatusAlert -> a WARN log
		cv.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert(Level.ERROR));

		// DSS 5.9+ :
		// Defines behavior in case if the signing certificate or its related POE(s) have been expired
		// Default : ExceptionOnStatusAlert -> interrupt the process
		cv.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());

		// DSS 5.9+ with changes since DSS 5.11+ (see below) :
		// RevocationDataLoadingStrategyFactory is used to instantiate RevocationDataLoadingStrategy
		// during the validation process, defining logic for loading OCSP or CRL data
		// Default : OCSPFirstRevocationDataLoadingStrategyFactory -> loads OCSP first,
		// 			 if not available or the response is invalid, then tries to load CRL
		// NOTE: Since DSS 5.11 a RevocationDataLoadingStrategyFactory shall be provided within CertificateVerifier, instead of RevocationDataLoadingStrategy.
		cv.setRevocationDataLoadingStrategyFactory(new OCSPFirstRevocationDataLoadingStrategyFactory());

		// DSS 5.11+ :
		// RevocationDataVerifier defines logic for accepting/rejecting revocation data during the validation process.
		// This included processing of revocation tokens extracted from a signature document,
		// as well as revocation tokens fetched from online sources.
		RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
		cv.setRevocationDataVerifier(revocationDataVerifier);

		// DSS 5.11+ :
		// Defines whether the first obtained revocation data still should be returned,
		// when none of the fetched revocation tokens have passed the verification.
		// Default : FALSE - none revocation data is returned, if all of them failed the verification.
		// NOTE : the property is used for signature extension, but not for validation.
		cv.setRevocationFallback(false);

		// end::demo[]

		final ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		final Date validationTime = new Date();

		// tag::rev-data-verifier[]
		// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
		// import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
		// import eu.europa.esig.dss.validation.RevocationDataVerifier;
		// import java.util.Arrays;
		// import java.util.HashMap;
		// import java.util.Map;

		// The following method is used to create a RevocationDataVerifier synchronized with a default validation policy
		revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();

		// It is also possible to instantiate a RevocationDataVerifier from a custom validation policy
		revocationDataVerifier = RevocationDataVerifier.createRevocationDataVerifierFromPolicy(validationPolicy);

		// A validation time can be also defined to enforce verification of specific cryptographic algorithms at the given time
		revocationDataVerifier = RevocationDataVerifier.createRevocationDataVerifierFromPolicyWithTime(validationPolicy, validationTime);

		// For customization directly in RevocationDataVerifier, the following methods may be used:

		// #setAcceptableDigestAlgorithms method is used to provide a list of DigestAlgorithms
		// to be accepted during the revocation data validation.
		// Default : collection of algorithms is synchronized with ETSI 119 312
		revocationDataVerifier.setAcceptableDigestAlgorithms(Arrays.asList(
				DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
				DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

		// #setAcceptableEncryptionAlgorithmKeyLength method defines a list of acceptable encryption algorithms and
		// their corresponding key length. Revocation tokens signed with other algorithms or with a key length smaller
		// than one defined within the map will be skipped.
		// Default : collection of algorithms is synchronized with ETSI 119 312
		Map<EncryptionAlgorithm, Integer> encryptionAlgos = new HashMap<>();
		encryptionAlgos.put(EncryptionAlgorithm.DSA, 2048);
		encryptionAlgos.put(EncryptionAlgorithm.RSA, 1900);
		encryptionAlgos.put(EncryptionAlgorithm.ECDSA, 256);
		encryptionAlgos.put(EncryptionAlgorithm.PLAIN_ECDSA, 256);
		revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(encryptionAlgos);

		// end::rev-data-verifier[]

	}

}
