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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Checks if signed file are present in an ASiC container
 */
public class SignedFilesPresentCheck extends ChainItem<XmlFC> {

	/** ASiC Container info */
	private final XmlContainerInfo containerInfo;

	/** The constraint message */
	private MessageTag message;

	/** The error message */
	private MessageTag error;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlFC}
	 * @param containerInfo {@link XmlContainerInfo}
	 * @param constraint {@link LevelConstraint}
	 */
	public SignedFilesPresentCheck(I18nProvider i18nProvider, XmlFC result, XmlContainerInfo containerInfo,
								   LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		if (ASiCContainerType.ASiC_S.equals(containerInfo.getContainerType())) { // ASiC-S one signed file in the root directory
			message = MessageTag.BBB_FC_ISFP_ASICS;
			error = MessageTag.BBB_FC_ISFP_ASICS_ANS;
			List<String> contentFiles = containerInfo.getContentFiles();
			if (Utils.isCollectionNotEmpty(contentFiles) && contentFiles.size() == 1) {
				String fileName = contentFiles.iterator().next();
				return isRootDirectoryFile(fileName);
			}
			return false;
		} else { // ASiC-E one or more signed files outside META-INF
			message = MessageTag.BBB_FC_ISFP_ASICE;
			error = MessageTag.BBB_FC_ISFP_ASICE_ANS;
			return Utils.isCollectionNotEmpty(containerInfo.getContentFiles());
		}
	}
	
	private boolean isRootDirectoryFile(String fileName) {
		return !fileName.contains("/") && !fileName.contains("\\");
	}

	@Override
	protected MessageTag getMessageTag() {
		return message;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return error;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

}
