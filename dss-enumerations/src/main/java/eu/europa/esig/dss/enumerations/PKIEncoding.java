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
package eu.europa.esig.dss.enumerations;

/**
 * Enumeration with the possible encoding for PKI encapsulation.
 * 
 * ETSI EN 319 132-1 5.1.3
 */
public enum PKIEncoding implements UriBasedEnum {

	/** http://uri.etsi.org/01903/v1.2.2#DER */
	DER("http://uri.etsi.org/01903/v1.2.2#DER"),

	/** http://uri.etsi.org/01903/v1.2.2#BER */
	BER("http://uri.etsi.org/01903/v1.2.2#BER"),

	/** http://uri.etsi.org/01903/v1.2.2#CER */
	CER("http://uri.etsi.org/01903/v1.2.2#CER"),

	/** http://uri.etsi.org/01903/v1.2.2#PER */
	PER("http://uri.etsi.org/01903/v1.2.2#PER"),

	/** http://uri.etsi.org/01903/v1.2.2#XER */
	XER("http://uri.etsi.org/01903/v1.2.2#XER");

	/** Encoding URI */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	PKIEncoding(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
