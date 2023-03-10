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
 * Defines QC type identifiers based on ETSI EN 319 412-5
 */
public enum QCTypeEnum implements QCType {

	/**
	 * id-etsi-qct-esign OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 1 }
	 * -- Certificate for electronic signatures as defined in Regulation (EU) No 910/2014
	 */
	QCT_ESIGN("qc-type-esign", "0.4.0.1862.1.6.1"),

	/**
	 * id-etsi-qct-eseal OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 2 }
	 * -- Certificate for electronic seals as defined in Regulation (EU) No 910/2014
	 */
	QCT_ESEAL("qc-type-eseal", "0.4.0.1862.1.6.2"),

	/**
	 * id-etsi-qct-web OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 3 }
	 * -- Certificate for website authentication as defined in Regulation (EU) No 910/2014
	 */
	QCT_WEB("qc-type-web", "0.4.0.1862.1.6.3");

	/** The QCType description */
	private final String description;

	/** The QCType OID */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String}
	 * @param oid {@link String}
	 */
	QCTypeEnum(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
