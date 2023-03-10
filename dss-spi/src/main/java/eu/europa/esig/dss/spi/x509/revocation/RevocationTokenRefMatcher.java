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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.Revocation;

/**
 * This class is used to validate a revocation reference against a revocation token
 *
 * @param <R> {@link Revocation}
 */
public interface RevocationTokenRefMatcher<R extends Revocation> {

	/**
	 * This method returns true if the reference is related to the provided token
	 * 
	 * @param token     the revocation token
	 * @param reference the revocation reference
	 * @return true if the reference refers to the token
	 */
	boolean match(RevocationToken<R> token, RevocationRef<R> reference);

	/**
	 * This method returns true if the reference is related to the encapsulated identifier
	 * 
	 * @param identifier the revocation token identifier
	 * @param reference the revocation reference
	 * @return true if the reference refers to the identifier
	 */
	boolean match(EncapsulatedRevocationTokenIdentifier<R> identifier, RevocationRef<R> reference);

}
