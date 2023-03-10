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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * The binary of an OCSP response token
 *
 */
public class OCSPResponseBinary extends EncapsulatedRevocationTokenIdentifier<OCSP> {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPResponseBinary.class);

	private static final long serialVersionUID = 6693521503459405568L;

	/** Basic OCSP response */
	private final transient BasicOCSPResp basicOCSPResp;

	/**
	 * Specifies origin of the OCSP Response from SignedData.CRLs element
	 * NOTE: Used in CAdES only!
	 */
	private transient ASN1ObjectIdentifier asn1ObjectIdentifier;

	/**
	 * Builds the {@code OCSPResponseBinary}
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 * @return {@link OCSPResponseBinary}
	 */
	public static OCSPResponseBinary build(BasicOCSPResp basicOCSPResp) {
		byte[] ocspRespBinary = DSSRevocationUtils.getEncodedFromBasicResp(basicOCSPResp);
		return new OCSPResponseBinary(basicOCSPResp, ocspRespBinary);
	}

	/**
	 * Default constructor
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 * @param encoded OCSP response binaries
	 */
	OCSPResponseBinary(BasicOCSPResp basicOCSPResp, byte[] encoded) {
		super(encoded);
		this.basicOCSPResp = basicOCSPResp;
	}

	/**
	 * Returns {@code BasicOCSPResp}
	 *
	 * @return {@link BasicOCSPResp}
	 */
	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}

	/**
	 * Returns the OCSP token binaries
	 *
	 * @return binaries
	 */
	public byte[] getBasicOCSPRespContent() {
		try {
			return basicOCSPResp.getEncoded();
		} catch (IOException e) {
			LOG.warn("Cannot get content bytes from BasicOCSPResponse of OCSPResponseIdentifier with id [{}]. Reason: [{}]", asXmlId(), e.getMessage());
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

	/**
	 * Gets the {@code ASN1ObjectIdentifier}
	 *
	 * @return {@link ASN1ObjectIdentifier}
	 */
	public ASN1ObjectIdentifier getAsn1ObjectIdentifier() {
		return asn1ObjectIdentifier;
	}

	/**
	 * Sets the {@code ASN1ObjectIdentifier}
	 *
	 * @param asn1ObjectIdentifier {@link ASN1ObjectIdentifier}
	 */
	public void setAsn1ObjectIdentifier(ASN1ObjectIdentifier asn1ObjectIdentifier) {
		this.asn1ObjectIdentifier = asn1ObjectIdentifier;
	} 

}
