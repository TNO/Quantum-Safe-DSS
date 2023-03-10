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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Contains grouped documents representing an ASiC container's content
 *
 */
public class ASiCContent implements Serializable {

	private static final long serialVersionUID = -6871206656998856916L;

	/** The original ASiC container */
	private DSSDocument asicContainer;

	/** The container type */
	private ASiCContainerType containerType;

	/** The zip comment */
	private String zipComment;

	/** The mimetype document */
	private DSSDocument mimeTypeDocument;

	/** The list of originally signed documents embedded into the container */
	private List<DSSDocument> signedDocuments = new ArrayList<>();

	/** The list of signature documents embedded into the container */
	private List<DSSDocument> signatureDocuments = new ArrayList<>();

	/** The list of manifest documents embedded into the container */
	private List<DSSDocument> manifestDocuments = new ArrayList<>();

	/** The list of archive manifest documents embedded into the container (ASiC with CAdES) */
	private List<DSSDocument> archiveManifestDocuments = new ArrayList<>();

	/** The list of timestamp documents embedded into the container (ASiC with CAdES) */
	private List<DSSDocument> timestampDocuments = new ArrayList<>();

	/** The list of unsupported documents embedded into the container */
	private List<DSSDocument> unsupportedDocuments = new ArrayList<>();

	/** The list of folders embedded into the container */
	private List<DSSDocument> folders = new ArrayList<>();

	/** The list of "package.zip" documents (ASiC-S) */
	private List<DSSDocument> containerDocuments = new ArrayList<>();

	/**
	 * Default constructor instantiating object with null values and empty list of documents
	 */
	public ASiCContent() {
		// empty
	}

	/**
	 * Gets the original ASiC container
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getAsicContainer() {
		return asicContainer;
	}

	/**
	 * Sets the original ASiC container
	 *
	 * @param asicContainer {@link DSSDocument}
	 */
	public void setAsicContainer(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	/**
	 * Gets the container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return containerType;
	}

	/**
	 * Sets the container type
	 *
	 * @param containerType {@link ASiCContainerType}
	 */
	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	/**
	 * Gets the zip comment
	 *
	 * @return {@link String} zip comment
	 */
	public String getZipComment() {
		return zipComment;
	}

	/**
	 * Sets the zip comment
	 *
	 * @param zipComment {@link String}
	 */
	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

	/**
	 * Gets mimetype document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getMimeTypeDocument() {
		return mimeTypeDocument;
	}

	/**
	 * Sets mimetype document
	 *
	 * @param mimeTypeDocument {@link DSSDocument}
	 */
	public void setMimeTypeDocument(DSSDocument mimeTypeDocument) {
		this.mimeTypeDocument = mimeTypeDocument;
	}

	/**
	 * Gets signature documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		return signatureDocuments;
	}

	/**
	 * Sets signature documents
	 *
	 * @param signatureDocuments a list of {@link DSSDocument}s
	 */
	public void setSignatureDocuments(List<DSSDocument> signatureDocuments) {
		this.signatureDocuments = signatureDocuments;
	}

	/**
	 * Gets manifest documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getManifestDocuments() {
		return manifestDocuments;
	}

	/**
	 * Sets manifest documents
	 *
	 * @param manifestDocuments a list of {@link DSSDocument}s
	 */
	public void setManifestDocuments(List<DSSDocument> manifestDocuments) {
		this.manifestDocuments = manifestDocuments;
	}

	/**
	 * Gets archive manifest documents (ASiC with CAdES only)
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveManifestDocuments() {
		return archiveManifestDocuments;
	}

	/**
	 * Sets archive manifest documents (ASiC with CAdES only)
	 *
	 * @param archiveManifestDocuments a list of {@link DSSDocument}s
	 */
	public void setArchiveManifestDocuments(List<DSSDocument> archiveManifestDocuments) {
		this.archiveManifestDocuments = archiveManifestDocuments;
	}

	/**
	 * Gets timestamp documents (ASiC with CAdES only)
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getTimestampDocuments() {
		return timestampDocuments;
	}

	/**
	 * Sets timestamp documents (ASiC with CAdES only)
	 *
	 * @param timestampDocuments a list of {@link DSSDocument}s
	 */
	public void setTimestampDocuments(List<DSSDocument> timestampDocuments) {
		this.timestampDocuments = timestampDocuments;
	}

	/**
	 * Gets signed documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	/**
	 * Sets signed documents
	 *
	 * @param signedDocuments a list of {@link DSSDocument}s
	 */
	public void setSignedDocuments(List<DSSDocument> signedDocuments) {
		this.signedDocuments = signedDocuments;
	}

	/**
	 * Gets unsupported documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getUnsupportedDocuments() {
		return unsupportedDocuments;
	}

	/**
	 * Sets unsupported documents
	 *
	 * @param unsupportedDocuments a list of {@link DSSDocument}s
	 */
	public void setUnsupportedDocuments(List<DSSDocument> unsupportedDocuments) {
		this.unsupportedDocuments = unsupportedDocuments;
	}

	/**
	 * Returns a list of folders present within the container
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getFolders() {
		return folders;
	}

	/**
	 * Sets a list of folders present within an archive
	 *
	 * @param folders a list of {@link DSSDocument}s
	 */
	public void setFolders(List<DSSDocument> folders) {
		this.folders = folders;
	}

	/**
	 * Gets "package.zip" documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getContainerDocuments() {
		return containerDocuments;
	}

	/**
	 * Sets package.zip" documents
	 *
	 * @param containerDocuments a list of {@link DSSDocument}s
	 */
	public void setContainerDocuments(List<DSSDocument> containerDocuments) {
		this.containerDocuments = containerDocuments;
	}

	/**
	 * This method returns a list of documents at the root level within the container
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getRootLevelSignedDocuments() {
		if (Utils.isCollectionEmpty(getSignedDocuments())) {
			return Collections.emptyList();
		}
		List<DSSDocument> rootLevelDocuments = new ArrayList<>();
		for (DSSDocument document : getSignedDocuments()) {
			if (document.getName() != null && !document.getName().contains("/") && !document.getName().contains("\\")) {
				rootLevelDocuments.add(document);
			}
		}
		return rootLevelDocuments;
	}
	
	/**
	 * Returns a list of all found manifest documents
	 * 
	 * @return list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		List<DSSDocument> allManifestsList = new ArrayList<>();
		allManifestsList.addAll(getManifestDocuments());
		allManifestsList.addAll(getArchiveManifestDocuments());
		return allManifestsList;
	}

	/**
	 * Gets all documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		List<DSSDocument> allDocuments = new ArrayList<>();
		// "mimetype" shall be the first file in the ASiC container;
		if (mimeTypeDocument != null) {
			allDocuments.add(mimeTypeDocument);
		}
		if (Utils.isCollectionNotEmpty(signedDocuments)) {
			allDocuments.addAll(signedDocuments);
		}
		if (Utils.isCollectionNotEmpty(signatureDocuments)) {
			allDocuments.addAll(signatureDocuments);
		}
		if (Utils.isCollectionNotEmpty(manifestDocuments)) {
			allDocuments.addAll(manifestDocuments);
		}
		if (Utils.isCollectionNotEmpty(archiveManifestDocuments)) {
			allDocuments.addAll(archiveManifestDocuments);
		}
		if (Utils.isCollectionNotEmpty(timestampDocuments)) {
			allDocuments.addAll(timestampDocuments);
		}
		if (Utils.isCollectionNotEmpty(unsupportedDocuments)) {
			allDocuments.addAll(unsupportedDocuments);
		}
		if (Utils.isCollectionNotEmpty(folders)) {
			allDocuments.addAll(folders);
		}

		return allDocuments;
	}

}
