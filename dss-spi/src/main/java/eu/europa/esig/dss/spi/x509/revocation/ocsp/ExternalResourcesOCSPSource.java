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

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.io.InputStream;
import java.util.List;

/**
 * This class is used to provide a collection of OCSP tokens by the user.
 *
 */
public class ExternalResourcesOCSPSource extends OfflineOCSPSource {

	private static final long serialVersionUID = -332201368387706970L;

	/**
	 * This constructor loads the OCSP responses from an array of <code>String</code>s representing resources.
	 *
	 * @param paths {@link String}(s)
	 */
	public ExternalResourcesOCSPSource(final String... paths) {
		for (final String pathItem : paths) {
			load(getClass().getResourceAsStream(pathItem));
		}
	}

	/**
	 * This constructor loads the OCSP responses from an array of <code>InputStream</code>s.
	 *
	 * @param inputStreams {@link InputStream}(s)
	 */
	public ExternalResourcesOCSPSource(final InputStream... inputStreams) {
		for (final InputStream inputStream : inputStreams) {
			load(inputStream);
		}
	}

	/**
	 * This constructor loads the OCSP responses from an array of <code>DSSDocument</code>s.
	 *
	 * @param dssDocuments {@link DSSDocument}(s)
	 */
	public ExternalResourcesOCSPSource(final DSSDocument... dssDocuments) {
		for (final DSSDocument document : dssDocuments) {
			load(document.openStream());
		}
	}

	/**
	 * This method adds the OCSP basic ocspResponses to the general list.
	 *
	 * @param inputStream {@link InputStream}
	 */
	private void load(final InputStream inputStream) {
		try (InputStream is = inputStream) {
			final OCSPResp ocspResp = new OCSPResp(is);
			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
			addBinary(OCSPResponseBinary.build(basicOCSPResp), RevocationOrigin.EXTERNAL);
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to load OCSP token : %s", e.getMessage()), e);
		}
	}

	@Override
	public List<RevocationToken<OCSP>> getRevocationTokens(CertificateToken certificate, CertificateToken issuer) {
		List<RevocationToken<OCSP>> revocationTokens = super.getRevocationTokens(certificate, issuer);
		for (RevocationToken<OCSP> revocationToken : revocationTokens) {
			revocationToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
		}
		return revocationTokens;
	}

}
