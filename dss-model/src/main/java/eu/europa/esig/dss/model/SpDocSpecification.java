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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a "SpDocSpecification" element
 *
 */
public class SpDocSpecification implements Serializable {

	private static final long serialVersionUID = -6362851298965394823L;

	/** The OID, e.g. OID : 2.2.25.1 */
	private String id;
	
	/** Optional description */
	private String description;
	
	/** Optional document references */
	private String[] documentationReferences;

	/** Specified in EN 319 132 */
	private ObjectIdentifierQualifier qualifier;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SpDocSpecification() {
		// empty
	}

	/**
	 * Get identifier
	 * 
	 * @return {@link String} id
	 */
	public String getId() {
		return id;
	}
	
	/**
	 * Set Identifier (URI or OID)
	 * 
	 * @param id 
	 *           {@link String} (eg : 2.2.25.1 for OID)
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Get description
	 * 
	 * @return {@link String} description
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Set description
	 * 
	 * @param description {@link String}
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Get documentation references
	 * 
	 * @return an array of {@link String} documentation references
	 */
	public String[] getDocumentationReferences() {
		return documentationReferences;
	}
	
	/**
	 * Set documentation references
	 * 
	 * @param documentationReferences an array of {@link String}s
	 */
	public void setDocumentationReferences(String... documentationReferences) {
		this.documentationReferences = documentationReferences;
	}

	/**
	 * Get a qualifier (used in XAdES)
	 * 
	 * @return {@link ObjectIdentifierQualifier}
	 */
	public ObjectIdentifierQualifier getQualifier() {
		return qualifier;
	}
	
	/**
	 * Set a qualifier (used in XAdES)
	 * 
	 * @param qualifier {@link ObjectIdentifierQualifier}
	 */
	public void setQualifier(ObjectIdentifierQualifier qualifier) {
		this.qualifier = qualifier;
	}



	@Override
	public int hashCode() {
		int result = id != null ? id.hashCode() : 0;
		result = 31 * result + (description != null ? description.hashCode() : 0);
		result = 31 * result + Arrays.hashCode(documentationReferences);
		result = 31 * result + (qualifier != null ? qualifier.hashCode() : 0);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof SpDocSpecification)) return false;

		SpDocSpecification that = (SpDocSpecification) o;

		if (!Objects.equals(id, that.id)) return false;
		if (!Objects.equals(description, that.description)) return false;
		// Probably incorrect - comparing Object[] arrays with Arrays.equals
		if (!Arrays.equals(documentationReferences, that.documentationReferences)) return false;
		return qualifier == that.qualifier;
	}

	@Override
	public String toString() {
		return "SpDocSpecification {id='" + id + "', description='" + description +
				"', documentationReferences=" + Arrays.toString(documentationReferences) +
				", qualifier=" + qualifier + "}";
	}

}
