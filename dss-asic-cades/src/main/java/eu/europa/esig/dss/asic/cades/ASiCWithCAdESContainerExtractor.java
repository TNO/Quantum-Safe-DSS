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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * The class is used to extract the content (documents) embedded into an ASiC with CAdES container
 */
public class ASiCWithCAdESContainerExtractor extends AbstractASiCContainerExtractor {

	/**
	 * The default constructor
	 *
	 * @param archive {@link DSSDocument} representing an ASiC with CAdES container
	 */
	public ASiCWithCAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	protected boolean isAllowedManifest(String entryName) {
		return ASiCUtils.isManifest(entryName);
	}

	@Override
	protected boolean isAllowedArchiveManifest(String entryName) {
		return ASiCUtils.isArchiveManifest(entryName);
	}

	@Override
	protected boolean isAllowedTimestamp(String entryName) {
		return ASiCUtils.isTimestamp(entryName);
	}

	@Override
	protected boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isCAdES(entryName);
	}

}
