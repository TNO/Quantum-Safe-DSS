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
package eu.europa.esig.dss.model.x509;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;

/**
 * This is the base class for the different types of tokens (certificate, OCSP,
 * CRL, Timestamp) used in the process of signature validation.
 */
@SuppressWarnings("serial")
public abstract class Token implements IdentifierBasedObject, Serializable {

	/**
	 * The token identifier to avoid computing more than one time the digest value
	 */
	private TokenIdentifier tokenIdentifier;

	/**
	 * The publicKey of the signed certificate(s)
	 */
	protected PublicKey publicKeyOfTheSigner;
	protected PublicKey altPublicKeyOfTheSigner;

	/**
	 * Indicates a status of token's signature
	 * Method isSignedBy(CertificateToken) must be called in order to obtain a signature validity
	 * Default: NOT_EVALUATED
	 */
	protected SignatureValidity signatureValidity = SignatureValidity.NOT_EVALUATED;
	protected SignatureValidity altSignatureValidity = SignatureValidity.NOT_EVALUATED;

	/**
	 * Indicates the token signature invalidity reason.
	 */
	protected String signatureInvalidityReason = "";

	protected String altSignatureInvalidityReason = "";


	/**
	 * The algorithm that was used to sign the token.
	 */
	protected SignatureAlgorithm signatureAlgorithm;
	protected SignatureAlgorithm altSignatureAlgorithm;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected Token() {
		// empty
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getDSSId() == null) ? 0 : getDSSId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Token other = (Token) obj;
		if (getDSSId() == null) {
			if (other.getDSSId() != null) {
				return false;
			}
		} else if (!getDSSId().equals(other.getDSSId())) {
			return false;
		}
		return true;
	}

	/**
	 * Checks if the certificate is self-signed. For all tokens different from
	 * CertificateToken this method always returns false. This method was introduced
	 * in order to manage in a uniform manner the different tokens.
	 *
	 * @return true if the token is self-signed
	 */
	public boolean isSelfSigned() {
		return false;
	}

	public abstract boolean isCertificateHybrid();

	/**
	 * Returns a DSS unique token identifier.
	 * 
	 * @return an instance of TokenIdentifier
	 */
	@Override
	public TokenIdentifier getDSSId() {
		if (tokenIdentifier == null) {
			tokenIdentifier = buildTokenIdentifier();
		}
		return tokenIdentifier;
	}
	
	/**
	 * Builds a token unique identifier
	 * 
	 * @return {@link TokenIdentifier}
	 */
	protected abstract TokenIdentifier buildTokenIdentifier();

	/**
	 * Returns a string representation of the unique DSS token identifier.
	 * 
	 * @return the unique string for the token
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

	/**
	 * Checks if the token is signed by the given token in the parameter.
	 * 
	 * @param token
	 *              the candidate to be tested
	 * @return true if this token is signed by the given certificate token
	 */
	public synchronized boolean isSignedBy(CertificateToken token) {
		if(this.isCertificateHybrid() && !token.isCertificateHybrid()){
			return false;
		}
		if (this.isCertificateHybrid() && token.isCertificateHybrid()){
			return isSignedBy(token.getPublicKey()) && isSignedBy(token.getAltPublicKey(), true);
		}
		return isSignedBy(token.getPublicKey());
	}



	/**
	 * Checks if the OCSP token is signed by the given publicKey
	 * 
	 * @param publicKey
	 *              the candidate to be tested
	 * @return true if this token is signed by the given public key
	 */
	public synchronized boolean isSignedBy(final PublicKey publicKey) {
		if (publicKeyOfTheSigner != null) {
			return publicKeyOfTheSigner.equals(publicKey);
		} else if (SignatureValidity.VALID == checkIsSignedBy(publicKey)) {
			if (!isSelfSigned()) {
				this.publicKeyOfTheSigner = publicKey;
			}
			return true;
		}
		return false;
	}

	public synchronized boolean isSignedBy(final PublicKey publicKey, boolean isAltKey) {
		if(!isAltKey){
			return isSignedBy(publicKey);
		}
		if (altPublicKeyOfTheSigner != null) {
			return altPublicKeyOfTheSigner.equals(publicKey);
		} else if (SignatureValidity.VALID == checkIsSignedByAlt(publicKey)) {
			if (!isSelfSigned()) {
				this.altPublicKeyOfTheSigner = publicKey;
			}
			return true;
		}
		return false;
	}

	/**
	 * Verifies if the current token has been signed by the specified publicKey
	 * @param publicKey {@link PublicKey} of a signing candidate
	 * 
	 * @return {@link SignatureValidity}
	 */
	protected abstract SignatureValidity checkIsSignedBy(final PublicKey publicKey);

	/**
	 * Verifies if the current token has been signed by the specified publicKey
	 * @param publicKey {@link PublicKey} of a signing candidate
	 *
	 * @return {@link SignatureValidity}
	 */
	protected abstract SignatureValidity checkIsSignedByAlt(final PublicKey publicKey);

	/**
	 * Returns the {@code X500Principal} of the certificate which was used to sign
	 * this token.
	 *
	 * @return the issuer's {@code X500Principal}
	 */
	public abstract X500Principal getIssuerX500Principal();

	/**
	 * Returns the creation date of this token.
	 * 
	 * This date is mainly used to retrieve the correct issuer within a collection
	 * of renewed certificates (new certificate with the same key pair).
	 * 
	 * @return the creation date of the token (notBefore for a certificate,
	 *         productionDate for revocation data,...)
	 */
	public abstract Date getCreationDate();

	/**
	 * This method returns the DSS abbreviation of the token. It is used for
	 * debugging purpose.
	 *
	 * @return an abbreviation for the certificate
	 */
	public String getAbbreviation() {
		return "?";
	}

	/**
	 * Returns the algorithm that was used to sign the token (ex:
	 * SHA1WithRSAEncryption, SHA1withRSA...).
	 *
	 * @return the used signature algorithm to sign this token
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Returns the alt algorithm that was used to sign the token (ex:
	 * SHA1WithRSAEncryption, SHA1withRSA...).
	 *
	 * @return the used alt signature algorithm to sign this token
	 */
	public SignatureAlgorithm getAltSignatureAlgorithm() {
		return altSignatureAlgorithm;
	}

	/**
	 * Indicates if the token's signature is intact.
	 * NOTE: The method isSignedBy(CertificateToken) must be called to set this flag.
	 *       Return false if the check isSignedBy() was not performed or
	 *       the signer's public key does not much.
	 *       In order to check if the validation has been performed, use
	 *       the method getSignatureValidity() that returns a three-state value.
	 *
	 * @return whether the token's signature is intact
	 */
	public boolean isSignatureIntact() {
		return SignatureValidity.VALID == signatureValidity;
	}

	/**
	 * Indicates if the token's alt signature is intact.
	 * NOTE: The method isSignedBy(CertificateToken) must be called to set this flag.
	 *       Return false if the check isSignedBy() was not performed or
	 *       the signer's public key does not much.
	 *       In order to check if the validation has been performed, use
	 *       the method getAltSignatureValidity() that returns a three-state value.
	 *
	 * @return whether the token's alt signature is intact
	 */
	public boolean isAltSignatureIntact() {
		return SignatureValidity.VALID == altSignatureValidity;
	}

	/**
	 * Indicates if the token's signature is intact and the token is valid (e.g. token's structure, message-imprint, etc.).
	 * NOTE: method isSignedBy(CertificateToken) shall be called before.
	 *
	 * @return {@code true} if the conditions corresponding to the token validity are met
	 */
	public boolean isValid() {
		if (altSignatureValidity == SignatureValidity.NOT_EVALUATED) {
			return isSignatureIntact();
		}
		else{
			return isSignatureIntact() && isAltSignatureIntact();
		}
	}
	
	/**
	 * Indicates a status of the token's signature validity. For each kind of token the
	 * method isSignedBy(CertificateToken) must be called to set this flag.
	 * 
	 * @return {@link SignatureValidity}
	 */
	public SignatureValidity getSignatureValidity() {
		return signatureValidity;
	}

	/**
	 * Indicates a status of the token's alt signature validity. For each kind of token the
	 * method isSignedBy(CertificateToken) must be called to set this flag.
	 *
	 * @return {@link SignatureValidity}
	 */
	public SignatureValidity getAltSignatureValidity() {
		return altSignatureValidity;
	}

	/**
	 * Returns the token invalidity reason when applicable.
	 * NOTE: method isSignedBy(CertificateToken) shall be called before.
	 *
	 * @return {@link String} containing the reason of token invalidity, empty string when token is valid
	 */
	public String getInvalidityReason() {
		return signatureInvalidityReason;
	}

	/**
	 * Returns the token invalidity reason when applicable.
	 * NOTE: method isSignedBy(CertificateToken) shall be called before.
	 *
	 * @return {@link String} containing the reason of token invalidity, empty string when token is valid
	 */
	public String getAltInvalidityReason() {
		return altSignatureInvalidityReason;
	}
	/**
	 * This method returns the public key of the token signer
	 * 
	 * @return the public key which signed this token
	 */
	public PublicKey getPublicKeyOfTheSigner() {
		return publicKeyOfTheSigner;
	}

	/**
	 * This method returns the alt public key of the token signer
	 *
	 * @return the alt public key which signed this token
	 */
	public PublicKey getAltPublicKeyOfTheSigner() {
		return altPublicKeyOfTheSigner;
	}

	/**
	 * Returns a string representation of the token.
	 *
	 * @param indentStr
	 *                  the indentation to use
	 * @return string representation of the token
	 */
	public abstract String toString(String indentStr);

	@Override
	public String toString() {
		return toString("");
	}

	/**
	 * Returns the encoded form of the wrapped token.
	 *
	 * @return the encoded form of the wrapped token
	 */
	public abstract byte[] getEncoded();

	/**
	 * Returns the digest value of the wrapped token
	 * 
	 * @param digestAlgorithm
	 *                        the requested digest algorithm
	 * @return the digest value in binaries
	 */
	public byte[] getDigest(DigestAlgorithm digestAlgorithm) {
		return getDSSId().getDigestValue(digestAlgorithm);
	}

}
