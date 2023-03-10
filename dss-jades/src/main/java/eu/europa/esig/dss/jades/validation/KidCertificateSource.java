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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * The certificate source containing a map of certificates by KIDs
 */
public class KidCertificateSource extends CommonCertificateSource {

	private static final long serialVersionUID = 8202022366337914356L;

	private static final Logger LOG = LoggerFactory.getLogger(KidCertificateSource.class);

	/** Map of kids and related certificate tokens */
	private Map<String, CertificateToken> mapByKid = new HashMap<>();

	/**
	 * Default constructor instantiating object with empty map of 'kid' identifiers and certificate tokens relation
	 */
	public KidCertificateSource() {
		// empty
	}

	@Override
	public CertificateToken addCertificate(CertificateToken certificateToAdd) {
		LOG.debug("kid is not provided (generate kid following the JAdES specification)");
		return addCertificate(DSSJsonUtils.generateKid(certificateToAdd), certificateToAdd);
	}

	/**
	 * Adds a certificate for a given 'kid' (JWS/JAdES)
	 * 
	 * @param kid         the used kid in the JWS/JAdES
	 * @param certificate the related certificate token
	 * @return the certificate
	 */
	public CertificateToken addCertificate(String kid, CertificateToken certificate) {
		CertificateToken addedCertificate = super.addCertificate(certificate);
		if (mapByKid.containsKey(kid)) {
			LOG.warn("kid {} is already known, the certificate will be replaced", kid);
		}
		mapByKid.put(kid, addedCertificate);
		return addedCertificate;
	}

	/**
	 * Gets a {@code CertificateToken} by the given KID
	 *
	 * @param kid {@link String} to get a certificate token with
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getCertificateByKid(String kid) {
		return mapByKid.get(kid);
	}

	@Override
	protected void reset() {
		super.reset();
		mapByKid = new HashMap<>();
	}

}
