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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;

/**
 * This signature scope is used to refer a counter-signed SignatureValue
 *
 */
public class CounterSignatureScope extends SignatureScope {

    private static final long serialVersionUID = 8599151632129217473L;

    /**
     * Default constructor
     *
     * @param masterSignatureId {@link String}
     * @param digest {@link Digest}
     */
    public CounterSignatureScope(final String masterSignatureId, Digest digest) {
        super(masterSignatureId, digest);
    }

    @Override
    public String getDescription() {
        return String.format("Master signature with Id : %s", getName());
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.COUNTER_SIGNATURE;
	}

}
