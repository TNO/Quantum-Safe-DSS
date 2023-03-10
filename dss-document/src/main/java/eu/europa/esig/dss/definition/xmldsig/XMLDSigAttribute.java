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
package eu.europa.esig.dss.definition.xmldsig;

import eu.europa.esig.dss.definition.DSSAttribute;

/**
 * Represents a collection of attributes defined in https://www.w3.org/TR/xmldsig-core1/
 *
 */
public enum XMLDSigAttribute implements DSSAttribute {

	/** Algorithm */
	ALGORITHM("Algorithm"),

	/** Encoding */
	ENCODING("Encoding"),

	/** Id */
	ID("Id"),

	/** MimeType */
	MIME_TYPE("MimeType"),

	/** Target */
	TARGET("Target"),

	/** Type */
	TYPE("Type"),

	/** URI */
	URI("URI");

	/** Attribute name */
	private final String attributeName;

	/**
	 * Default constructor
	 *
	 * @param attributeName {@link String}
	 */
	XMLDSigAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
