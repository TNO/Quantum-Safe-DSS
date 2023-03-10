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
package eu.europa.esig.dss.model.x509.extension;

import java.io.Serializable;

/**
 * PdsLocation::= SEQUENCE {
 *  url IA5String,
 *  language PrintableString (SIZE(2))} --ISO 639-1 language code
 */
public class PdsLocation implements Serializable {

    private static final long serialVersionUID = 8286970864745135226L;

    /** The URL */
    private String url;

    /** The language */
    private String language;

    /**
     * Default constructor instantiating object with null values
     */
    public PdsLocation() {
        // empty
    }

    /**
     * Returns URL
     *
     * @return {@link String}
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets URL
     *
     * @param url {@link String}
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Returns the language
     *
     * @return {@link String}
     */
    public String getLanguage() {
        return language;
    }

    /**
     * Sets language
     *
     * @param language {@link String}
     */
    public void setLanguage(String language) {
        this.language = language;
    }

}
