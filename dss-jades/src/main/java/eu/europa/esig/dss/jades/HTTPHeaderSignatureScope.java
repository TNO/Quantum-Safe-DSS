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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * The signature scope used to define the signed payload with HTTPHeader SigD Mechanism
 */
public class HTTPHeaderSignatureScope extends SignatureScope {

	private static final long serialVersionUID = -8682422499573648984L;

	/**
	 * The default constructor
	 *
	 * @param digest {@link Digest} of the computed JWS Payload
	 */
	public HTTPHeaderSignatureScope(Digest digest) {
		this("HttpHeaders payload", digest);
	}

	/**
	 * Constructor with document name
	 *
	 * @param name {@link String} document name
	 * @param digest {@link Digest} of the document
	 */
	protected HTTPHeaderSignatureScope(String name, Digest digest) {
		super(name, digest);
	}

	@Override
	public String getDescription() {
		return "Payload value digest";
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
