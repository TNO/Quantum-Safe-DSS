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
package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.definition.DSSAttribute;

/**
 * Represents a collection of attributes defined in ASiC XSD schema
 *
 */
public enum ASiCAttribute implements DSSAttribute {

	/** URI */
	URI("URI"),

	/** MimeType */
	MIME_TYPE("MimeType"),

	/** Rootfile */
	ROOTFILE("Rootfile"),
	
	/** Critical */
	CRITICAL("Critical");
	
	/** Attribute name */
	private final String attributeName;

	/**
	 * Default constructor
	 *
	 * @param attributeName {@link String}
	 */
	ASiCAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
