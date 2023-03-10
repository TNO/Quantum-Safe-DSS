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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.TimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A common implementation of {@code AdvancedSignature}
 */
public abstract class DefaultAdvancedSignature implements AdvancedSignature {

	private static final long serialVersionUID = 6452189007886779360L;

	/**
	 * In case of a detached signature this is the signed document.
	 */
	protected List<DSSDocument> detachedContents;

	/**
	 * In case of a ASiC-S signature this is the archive or manifest content.
	 */
	private List<DSSDocument> containerContents;
	
	/**
	 * In case of a ASiC-E signature this is the found related manifest file.
	 */
	protected ManifestFile manifestFile;

	/**
	 * This variable contains a list of reference validations (reference tag for
	 * XAdES or message-digest for CAdES)
	 */
	protected List<ReferenceValidation> referenceValidations;

	/**
	 * This variable contains the result of the signature mathematical validation. It is initialised when the method
	 * {@code checkSignatureIntegrity} is called.
	 */
	protected SignatureCryptographicVerification signatureCryptographicVerification;

	/**
	 * A list of error messages occurred during a structure validation
	 */
	protected List<String> structureValidationMessages;

	/**
	 * The offline copy of a CertificateVerifier
	 */
	protected CertificateVerifier offlineCertificateVerifier;

	/**
	 * The certificate source of a signing certificate
	 */
	protected CertificateSource signingCertificateSource;

	/**
	 * Cached offline signature certificate source
	 */
	protected SignatureCertificateSource offlineCertificateSource;

	/**
	 * Cached offline signature CRL source
	 */
	protected OfflineCRLSource signatureCRLSource;

	/**
	 * Cached offline signature OCSP source
	 */
	protected OfflineOCSPSource signatureOCSPSource;

	/**
	 * Cached offline signature timestamp source
	 */
	protected TimestampSource signatureTimestampSource;

	/**
	 * Cached list of embedded counter signatures
	 */
	protected List<AdvancedSignature> counterSignatures;

	/**
	 * The master signature in case if the current signature is a counter signature
	 */
	private AdvancedSignature masterSignature;

	/**
	 * The SignaturePolicy identifier
	 */
	protected SignaturePolicy signaturePolicy;

	/**
	 * A list of found {@code SignatureScope}s
	 */
	private List<SignatureScope> signatureScopes;

	/**
	 * The name of a signature file
	 */
	private String signatureFilename;
	
	/**
	 * Unique signature identifier
	 */
	protected SignatureIdentifier signatureIdentifier;

	/**
	 * Performs a conformance check for the signature to a given profile
	 */
	private transient BaselineRequirementsChecker<?> baselineRequirementsChecker;

	/**
	 * Cached instance of the signing certificate token
	 */
	private CertificateToken signingCertificateToken;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected DefaultAdvancedSignature() {
		// empty
	}
	
	/**
	 * Returns a builder to define and build a signature Id
	 * 
	 * @return {@link SignatureIdentifierBuilder}
	 */
	protected abstract SignatureIdentifierBuilder getSignatureIdentifierBuilder();

	@Override
	public void setSigningCertificateSource(CertificateSource signingCertificateSource) {
		this.signingCertificateSource = signingCertificateSource;
	}

	@Override
	public String getSignatureFilename() {
		return signatureFilename;
	}

	@Override
	public void setSignatureFilename(String signatureFilename) {
		this.signatureFilename = signatureFilename;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}
	
	@Override
	public List<DSSDocument> getContainerContents() {
		return containerContents;
	}
	
	@Override
	public void setContainerContents(List<DSSDocument> containerContents) {
		this.containerContents = containerContents;
	}
	
	@Override
	public ManifestFile getManifestFile() {
		return manifestFile;
	}
	
	@Override
	public void setManifestFile(ManifestFile manifestFile) {
		this.manifestFile = manifestFile;
	}
	
	@Override
	public SignatureIdentifier getDSSId() {
		if (signatureIdentifier == null) {
			signatureIdentifier = getSignatureIdentifierBuilder().build();
		}
		return signatureIdentifier;
	}
	
	@Override
	public String getId() {
		return getDSSId().asXmlId();
	}
	
	@Override
	public ListCertificateSource getCompleteCertificateSource() {
		ListCertificateSource certificateSource = new ListCertificateSource(getCertificateSource());
		certificateSource.addAll(getTimestampSource().getTimestampCertificateSources());
		certificateSource.addAll(getCounterSignaturesCertificateSource());
		return certificateSource;
	}

	@Override
	public ListRevocationSource<CRL> getCompleteCRLSource() {
		ListRevocationSource<CRL> crlSource = new ListRevocationSource<>(getCRLSource());
		crlSource.addAll(getTimestampSource().getTimestampCRLSources());
		crlSource.addAll(getCounterSignaturesCRLSource());
		return crlSource;
	}

	@Override
	public ListRevocationSource<OCSP> getCompleteOCSPSource() {
		ListRevocationSource<OCSP> ocspSource = new ListRevocationSource<>(getOCSPSource());
		ocspSource.addAll(getTimestampSource().getTimestampOCSPSources());
		ocspSource.addAll(getCounterSignaturesOCSPSource());
		return ocspSource;
	}
	
	/**
	 * Returns a merged certificate source for values incorporated within counter signatures
	 * 
	 * @return {@link ListCertificateSource}
	 */
	protected ListCertificateSource getCounterSignaturesCertificateSource() {
		ListCertificateSource certificateSource = new ListCertificateSource();
		for (AdvancedSignature counterSignature : getCounterSignatures()) {
			certificateSource.addAll(counterSignature.getCompleteCertificateSource());
		}
		return certificateSource;
	}

	/**
	 * Returns a merged CRL source for values incorporated within counter signatures
	 * 
	 * @return CRL {@link ListRevocationSource}
	 */
	protected ListRevocationSource<CRL> getCounterSignaturesCRLSource() {
		ListRevocationSource<CRL> crlSource = new ListRevocationSource<>();
		for (AdvancedSignature counterSignature : getCounterSignatures()) {
			crlSource.addAll(counterSignature.getCompleteCRLSource());
		}
		return crlSource;
	}

	/**
	 * Returns a merged OCSP source for values incorporated within counter signatures
	 * 
	 * @return OCSP {@link ListRevocationSource}
	 */
	protected ListRevocationSource<OCSP> getCounterSignaturesOCSPSource() {
		ListRevocationSource<OCSP> crlSource = new ListRevocationSource<>();
		for (AdvancedSignature counterSignature : getCounterSignatures()) {
			crlSource.addAll(counterSignature.getCompleteOCSPSource());
		}
		return crlSource;
	}
	
	/**
	 * This method resets the source of certificates. It must be called when 
	 * any certificate is added to the KeyInfo or CertificateValues (XAdES), or 'xVals' (JAdES).
	 * 
	 * NOTE: used in XAdES and JAdES
	 */
	public void resetCertificateSource() {
		offlineCertificateSource = null;
	}

	/**
	 * This method resets the sources of the revocation data. It must be called when -LT level is created.
	 * 
	 * NOTE: used in XAdES and JAdES
	 */
	public void resetRevocationSources() {
		signatureCRLSource = null;
		signatureOCSPSource = null;
	}

	/**
	 * This method resets the timestamp source. It must be called when -LT level is created.
	 * 
	 * NOTE: used in XAdES and JAdES
	 */
	public void resetTimestampSource() {
		signatureTimestampSource = null;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * 5.6.3 Signature Verification Process
	 * ...the public key from the first certificate identified in the sequence
	 * of certificate identifiers from SigningCertificate shall be the key used
	 * to verify the digital signature.
	 *
	 * @return {@link CandidatesForSigningCertificate}
	 */
	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {
		return getCertificateSource().getCandidatesForSigningCertificate(signingCertificateSource);
	}

	@Override
	public void prepareOfflineCertificateVerifier(final CertificateVerifier certificateVerifier) {
		offlineCertificateVerifier = new CertificateVerifierBuilder(certificateVerifier).buildOfflineAndSilentCopy();
	}

	/**
	 * Returns an unmodifiable list of all certificate tokens encapsulated in the
	 * signature
	 * 
	 * @see eu.europa.esig.dss.validation.AdvancedSignature#getCertificates()
	 */
	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
	}

	@Override
	public void setMasterSignature(final AdvancedSignature masterSignature) {
		this.masterSignature = masterSignature;
	}

	@Override
	public AdvancedSignature getMasterSignature() {
		return masterSignature;
	}
	
	@Override
	public boolean isCounterSignature() {
		return masterSignature != null;
	}

	@Override
	public SignatureCryptographicVerification getSignatureCryptographicVerification() {
		if (signatureCryptographicVerification == null) {
			checkSignatureIntegrity();
		}
		return signatureCryptographicVerification;
	}
	
	@Override
	public List<SignerRole> getSignerRoles() {
		List<SignerRole> signerRoles = new ArrayList<>();
		List<SignerRole> claimedSignerRoles = getClaimedSignerRoles();
		if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
			signerRoles.addAll(claimedSignerRoles);
		}
		List<SignerRole> certifiedSignerRoles = getCertifiedSignerRoles();
		if (Utils.isCollectionNotEmpty(certifiedSignerRoles)) {
			signerRoles.addAll(certifiedSignerRoles);
		}
		List<SignerRole> signedAssertionSignerRoles = getSignedAssertions();
		if (Utils.isCollectionNotEmpty(signedAssertionSignerRoles)) {
			signerRoles.addAll(signedAssertionSignerRoles);
		}
		return signerRoles;
	}

	@Override
	public CertificateToken getSigningCertificateToken() {
		if (signingCertificateToken == null) {
			// This ensures that the variable candidatesForSigningCertificate has been initialized
			CandidatesForSigningCertificate candidatesForSigningCertificate = getCertificateSource()
					.getCandidatesForSigningCertificate(signingCertificateSource);
			// This ensures that the variable signatureCryptographicVerification has been initialized
			signatureCryptographicVerification = getSignatureCryptographicVerification();
			final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
			if (theCertificateValidity != null && theCertificateValidity.isValid()) {
				return theCertificateValidity.getCertificateToken();
			}
			final CertificateValidity theBestCandidate = candidatesForSigningCertificate.getTheBestCandidate();
			if (theBestCandidate != null) {
				signingCertificateToken = theBestCandidate.getCertificateToken();
			}
		}
		return signingCertificateToken;
	}

	@Override
	public List<String> getStructureValidationResult() {
		if (Utils.isCollectionEmpty(structureValidationMessages)) {
			structureValidationMessages = validateStructure();
		}
		return structureValidationMessages;
	}
	
	/**
	 * This method processes the structure validation of the signature.
	 *
	 * @return list of {@link String} errors
	 */
	protected List<String> validateStructure() {
		// not implemented by default
		return Collections.emptyList();
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void findSignatureScope(SignatureScopeFinder signatureScopeFinder) {
		signatureScopes = signatureScopeFinder.findSignatureScope(this);
	}

	@Override
	public List<SignatureScope> getSignatureScopes() {
		return signatureScopes;
	}
	
	@Override
	public List<TimestampToken> getContentTimestamps() {
		return getTimestampSource().getContentTimestamps();
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {
		return getTimestampSource().getSignatureTimestamps();
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {
		return getTimestampSource().getTimestampsX1();
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {
		return getTimestampSource().getTimestampsX2();
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {
		return getTimestampSource().getArchiveTimestamps();
	}

	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		return getTimestampSource().getDocumentTimestamps();
	}
	
	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		return getTimestampSource().getDetachedTimestamps();
	}

	@Override
	public List<TimestampToken> getAllTimestamps() {
		return getTimestampSource().getAllTimestamps();
	}

	@Override
	public SignaturePolicy getSignaturePolicy() {
		if (signaturePolicy == null) {
			signaturePolicy = buildSignaturePolicy();
		}
		return signaturePolicy;
	}

	/**
	 * This method extracts a signature policy from a signature and builds the object
	 *
	 * @return {@link SignaturePolicy}
	 */
	protected abstract SignaturePolicy buildSignaturePolicy();

	/**
	 * Returns a cached instance of the {@code BaselineRequirementsChecker}
	 *
	 * @return {@link BaselineRequirementsChecker}
	 */
	@SuppressWarnings("rawtypes")
	protected BaselineRequirementsChecker getBaselineRequirementsChecker() {
		if (baselineRequirementsChecker == null) {
			baselineRequirementsChecker = createBaselineRequirementsChecker();
		}
		return baselineRequirementsChecker;
	}

	/**
	 * Instantiates a {@code BaselineRequirementsChecker} according to the signature format
	 *
	 * @return {@link BaselineRequirementsChecker}
	 */
	@SuppressWarnings("rawtypes")
	protected abstract BaselineRequirementsChecker createBaselineRequirementsChecker();

	/**
	 * Checks if the signature is conformant to AdES-BASELINE-B level
	 *
	 * @return TRUE if the B-level is present, FALSE otherwise
	 */
	public boolean hasBProfile() {
		return getBaselineRequirementsChecker().hasBaselineBProfile();
	}

	/**
	 * Checks if the T-level is present in the signature
	 *
	 * @return TRUE if the T-level is present, FALSE otherwise
	 */
	public boolean hasTProfile() {
		return getBaselineRequirementsChecker().hasBaselineTProfile();
	}

	/**
	 * Checks if the LT-level is present in the signature
	 *
	 * @return TRUE if the LT-level is present, FALSE otherwise
	 */
	public boolean hasLTProfile() {
		return getBaselineRequirementsChecker().hasBaselineLTProfile();
	}

	/**
	 * Checks if the LTA-level is present in the signature
	 *
	 * @return TRUE if the LTA-level is present, FALSE otherwise
	 */
	public boolean hasLTAProfile() {
		return getBaselineRequirementsChecker().hasBaselineLTAProfile();
	}

	@Override
	public boolean areAllSelfSignedCertificates() {
		ListCertificateSource certificateSources = getCompleteCertificateSource();
		boolean certificateFound = certificateSources.getNumberOfCertificates() > 0;
		return certificateFound && certificateSources.isAllSelfSigned();
	}
	
	@Override
	public boolean isDocHashOnlyValidation() {
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DSSDocument dssDocument : detachedContents) {
				if (!(dssDocument instanceof DigestDocument)) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	@Override
	public boolean isHashOnlyValidation() {
		// TODO: not implemented yet
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DefaultAdvancedSignature)) {
			return false;
		}
		DefaultAdvancedSignature das = (DefaultAdvancedSignature) obj;
		return getDSSId().equals(das.getDSSId());
	}

	@Override
	public int hashCode() {
		return getDSSId().hashCode();
	}
	
	@Override
	public String toString() {
		return String.format("%s Signature with Id : %s", getSignatureForm(), getId());
	}

}
