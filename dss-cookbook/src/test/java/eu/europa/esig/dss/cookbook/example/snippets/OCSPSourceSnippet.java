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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

import javax.sql.DataSource;
import java.sql.SQLException;

public class OCSPSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) throws SQLException {

		OCSPSource ocspSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		// import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

		DataSource dataSource = null;
		
		// tag::demo-online[]
		// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
		// import eu.europa.esig.dss.service.SecureRandomNonceSource;
		// import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
		// import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;

		// Instantiates a new OnlineOCSPSource object
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		
		// Allows setting an implementation of the `DataLoader` interface,
		// processing a querying of a remote revocation server. 
		// `CommonsDataLoader` instance is used by default.
		onlineOCSPSource.setDataLoader(new OCSPDataLoader());
		
		// Defines an arbitrary integer used in OCSP source querying in order to prevent a replay attack. 
		// Default : null (not used by default).
		onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());
		
		// Defines a DigestAlgorithm being used to generate a CertificateID in order to complete an OCSP request. 
		// OCSP servers supporting multiple hash functions may produce a revocation response 
		// with a digest algorithm depending on the provided CertificateID's algorithm. 
		// Default : SHA1 (as a mandatory requirement to be implemented by OCSP servers. See RFC 5019).
		onlineOCSPSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA1);
		
		// end::demo-online[]

		// tag::demo-cached[]
		// import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
		// import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
		// import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

		// Creates an instance of JdbcCacheOCSPSource
		JdbcCacheOCSPSource cacheOCSPSource = new JdbcCacheOCSPSource();

		// Initialize the JdbcCacheConnector
		JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);

		// Set the JdbcCacheConnector
		cacheOCSPSource.setJdbcCacheConnector(jdbcCacheConnector);

		// Allows definition of an alternative dataLoader to be used to access a revocation
		// from online sources if a requested revocation is not present in the repository or has been expired (see below).
		cacheOCSPSource.setProxySource(onlineOCSPSource);

		// All setters accept values in seconds
		Long threeMinutes = (long) (60 * 3); // seconds * minutes

		// If "nextUpdate" field is not defined for a revocation token, the value of "defaultNextUpdateDelay"
		// will be used in order to determine when a new revocation data should be requested.
		// If the current time is not beyond the "thisUpdate" time + "defaultNextUpdateDelay",
		// then a revocation data will be retrieved from the repository source, otherwise a new revocation data
		// will be requested from a proxiedSource.
		// Default : null (a new revocation data will be requested of "nestUpdate" field is not defined).
		cacheOCSPSource.setDefaultNextUpdateDelay(threeMinutes);

		// Creates an SQL table
		cacheOCSPSource.initTable();

		// Extract OCSP for a certificate
		OCSPToken ocspRevocationToken = cacheOCSPSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo-cached[]

	}

}
