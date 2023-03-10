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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static eu.europa.esig.dss.enumerations.SignatureLevel.JAdES_BASELINE_LT;

/**
 * Creates an LT-level of a JAdES signature
 */
public class JAdESLevelBaselineLT extends JAdESLevelBaselineT {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESLevelBaselineLT.class);

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public JAdESLevelBaselineLT(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters params) {
		super.extendSignatures(signatures, params);

		boolean ltLevelRequired = false;

		// Reset sources
		for (AdvancedSignature signature : signatures) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			if (!ltLevelExtensionRequired(jadesSignature, params)) {
				continue;
			}

			/**
			 * In all cases the -LT level need to be regenerated.
			 */
			assertSignatureValid(jadesSignature, params);

			// Data sources can already be loaded in memory (force reload)
			jadesSignature.resetCertificateSource();
			jadesSignature.resetRevocationSources();
			jadesSignature.resetTimestampSource();

			ltLevelRequired = true;
		}

		if (!ltLevelRequired) {
			return;
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentValidator.getValidationData(signatures);

		// Append ValidationData
		for (AdvancedSignature signature : signatures) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			if (!ltLevelExtensionRequired(jadesSignature, params)) {
				continue;
			}

			assertExtendSignatureToLTPossible(jadesSignature, params);

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();

			removeOldCertificateValues(jadesSignature, etsiUHeader);
			removeOldRevocationValues(jadesSignature, etsiUHeader);

			final ValidationData validationDataForInclusion = validationDataContainer.getCompleteValidationDataForSignature(signature);

			Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
			Set<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
			Set<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();

			incorporateXVals(etsiUHeader, certificateValuesToAdd, params.isBase64UrlEncodedEtsiUComponents());
			incorporateRVals(etsiUHeader, crlsToAdd, ocspsToAdd, params.isBase64UrlEncodedEtsiUComponents());
		}
	}

	private void removeOldCertificateValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(JAdESHeaderParameterNames.X_VALS);
		jadesSignature.resetCertificateSource();
	}

	private void removeOldRevocationValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(JAdESHeaderParameterNames.R_VALS);
		jadesSignature.resetRevocationSources();
	}

	/**
	 * Builds and returns 'xVals' JSONArray
	 * 
	 * @param certificateValuesToAdd a set of {@link CertificateToken}s to add
	 * @return {@link JSONArray} 'xVals' JSONArray
	 */
	@SuppressWarnings("unchecked")
	protected JSONArray getXVals(Set<CertificateToken> certificateValuesToAdd) {
		JSONArray xValsArray = new JSONArray();
		for (CertificateToken certificateToken : certificateValuesToAdd) {
			xValsArray.add(getX509CertObject(certificateToken));
		}
		return xValsArray;
	}

	@SuppressWarnings("unchecked")
	private JSONObject getX509CertObject(CertificateToken certificateToken) {
		JSONObject pkiOb = new JSONObject();
		pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(certificateToken.getEncoded()));

		JSONObject x509Cert = new JSONObject();
		x509Cert.put(JAdESHeaderParameterNames.X509_CERT, pkiOb);
		return x509Cert;
	}

	/**
	 * Incorporates the provided set of certificates into {@code etsiUHeader}
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} to update
	 * @param certificateValuesToAdd a set of {@link CertificateToken}s to add
	 * @param base64UrlEncoded if members of the etsiU array shall be base64UrlEncoded
	 */
	protected void incorporateXVals(JAdESEtsiUHeader etsiUHeader, Set<CertificateToken> certificateValuesToAdd, boolean base64UrlEncoded) {
		if (Utils.isCollectionNotEmpty(certificateValuesToAdd)) {
			JSONArray xVals = getXVals(certificateValuesToAdd);
			etsiUHeader.addComponent(JAdESHeaderParameterNames.X_VALS, xVals, base64UrlEncoded);
		}
	}

	/**
	 * Builds and returns 'rVals' JsonObject
	 * 
	 * @param crlsToAdd  a set of {@link CRLToken}s to add
	 * @param ocspsToAdd a set of {@link OCSPToken}s to add
	 * @return {@link JsonObject} 'rVals' object
	 */
	protected JsonObject getRVals(Set<CRLToken> crlsToAdd, Set<OCSPToken> ocspsToAdd) {
		JsonObject rValsObject = new JsonObject();
		if (Utils.isCollectionNotEmpty(crlsToAdd)) {
			rValsObject.put(JAdESHeaderParameterNames.CRL_VALS, getCrlVals(crlsToAdd));
		}
		if (Utils.isCollectionNotEmpty(ocspsToAdd)) {
			rValsObject.put(JAdESHeaderParameterNames.OCSP_VALS, getOcspVals(ocspsToAdd));
		}
		return rValsObject;
	}

	@SuppressWarnings("unchecked")
	private JSONArray getCrlVals(Set<CRLToken> crlsToAdd) {
		JSONArray array = new JSONArray();
		for (CRLToken crlToken : crlsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(crlToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	@SuppressWarnings("unchecked")
	private JSONArray getOcspVals(Set<OCSPToken> ocspsToAdd) {
		JSONArray array = new JSONArray();
		for (OCSPToken ocspToken : ocspsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(ocspToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	/**
	 * Incorporates the provided set of certificates into {@code etsiUHeader}
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} to update
	 * @param crlsToAdd a set of {@link CRLToken}s to add
	 * @param ocspsToAdd a set of {@link OCSPToken}s to add
	 * @param base64UrlEncoded if members of the etsiU array shall be base64UrlEncoded
	 */
	protected void incorporateRVals(JAdESEtsiUHeader etsiUHeader, Set<CRLToken> crlsToAdd,
									Set<OCSPToken> ocspsToAdd, boolean base64UrlEncoded) {
		if (Utils.isCollectionNotEmpty(crlsToAdd) || Utils.isCollectionNotEmpty(ocspsToAdd)) {
			JsonObject rVals = getRVals(crlsToAdd, ocspsToAdd);
			etsiUHeader.addComponent(JAdESHeaderParameterNames.R_VALS, rVals, base64UrlEncoded);
		}
	}

	/**
	 * This method checks the signature integrity and throws a {@code DSSException} if the signature is broken.
	 *
	 * @param jadesSignature {@link JAdESSignature} to verify
	 * @param params {@link JAdESSignatureParameters} the used signature parameters
	 * @throws DSSException in case of the cryptographic signature verification fails
	 */
	protected void assertSignatureValid(JAdESSignature jadesSignature, JAdESSignatureParameters params) throws DSSException {
		if (params.isGenerateTBSWithoutCertificate() && jadesSignature.getCertificateSource().getNumberOfCertificates() == 0) {
			LOG.debug("Extension of a signature without TBS certificate. Signature validity is not checked.");
			return;
		}

		final SignatureCryptographicVerification signatureCryptographicVerification = jadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
	}

	private boolean ltLevelExtensionRequired(JAdESSignature jadesSignature, JAdESSignatureParameters parameters) {
		return JAdES_BASELINE_LT.equals(parameters.getSignatureLevel()) || !jadesSignature.hasLTAProfile();
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (JAdES_BASELINE_LT.equals(signatureLevel) && jadesSignature.hasLTAProfile()) {
			throw new IllegalInputException(String.format(
					"Cannot extend signature to '%s'. The signature is already extended with LTA level.", signatureLevel));
		} else if (jadesSignature.getCertificateSource().getNumberOfCertificates() == 0) {
			throw new IllegalInputException("Cannot extend signature. The signature does not contain certificates.");
		} else if (jadesSignature.areAllSelfSignedCertificates()) {
			throw new IllegalInputException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
