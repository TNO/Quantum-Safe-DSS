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
package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;

import java.io.Serializable;

/**
 * Loads files
 */
public interface DSSFileLoader extends Serializable {
	
	/**
	 * Returns DSSDocument from the provided url
	 * @param url {@link String} url of the document to obtain
	 * @return {@link DSSDocument} retrieved document
	 * @throws DSSException in case of DataLoader error
	 */
	DSSDocument getDocument(final String url) throws DSSException;
	
	/**
	 * Removes the file from FileSystem with the given url
	 * @param url {@link String} url of the remote file location (the same what was used on file saving)
	 * @return TRUE when file was successfully deleted, FALSE otherwise
	 */
	boolean remove(final String url);

}
