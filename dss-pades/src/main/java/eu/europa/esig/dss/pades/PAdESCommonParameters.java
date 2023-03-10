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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.pdf.PdfSignatureCache;

import java.io.Serializable;
import java.util.Date;

/**
 * Defines a list of common PAdES parameters between signature and timestamps
 *
 */
public interface PAdESCommonParameters extends Serializable {
	
	/**
	 * Returns a claimed signing time
	 * 
	 * @return {@link Date}
	 */
	Date getSigningDate();
	
	/**
	 * Returns Filter value
	 * 
	 * @return {@link String} filter
	 */
	String getFilter();
	
	/**
	 * Returns SubFilter value
	 * 
	 * @return {@link String} subFilter
	 */
	String getSubFilter();
	
	/**
	 * Returns {@link SignatureImageParameters} for field's visual representation
	 * 
	 * @return {@link SignatureImageParameters}
	 */
	SignatureImageParameters getImageParameters();
	
	/**
	 * Returns a length of the reserved /Contents attribute
	 * 
	 * @return int content size
	 */
	int getContentSize();
	
	/**
	 * Returns a DigestAlgorithm to be used to hash the signed/timestamped data
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();
	
	/**
	 * Returns a password used to encrypt a document
	 * 
	 * @return char array representing a password string
	 */
	char[] getPasswordProtection();

	/**
	 * Returns name of an application used to create a signature/timestamp
	 *
	 * @return {@link String}
	 */
	String getAppName();

	/**
	 * Returns the deterministic identifier to be used to define a documentId on signing/timestamping, when necessary
	 *
	 * @return the unique ID for the document
	 */
	String getDeterministicId();

	/**
	 * Returns an internal variable, used to cache data in order to accelerate signing process
	 *
	 * @return {@link PdfSignatureCache}
	 */
	PdfSignatureCache getPdfSignatureCache();

	/**
	 * This method re-inits signature parameters to clean temporary settings
	 */
	void reinit();

}
