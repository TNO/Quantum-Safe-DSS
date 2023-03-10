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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the referenced data is intact
 */
public class ReferenceDataIntactCheck extends ChainItem<XmlCV> {

	/** The reference DigestMatcher */
	private final XmlDigestMatcher digestMatcher;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCV}
	 * @param digestMatcher {@link XmlDigestMatcher}
	 * @param constraint {@link LevelConstraint}
	 */
	public ReferenceDataIntactCheck(I18nProvider i18nProvider, XmlCV result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.digestMatcher = digestMatcher;
	}

	@Override
	protected boolean process() {
		return digestMatcher.isDataIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (digestMatcher.getType()) {
			case MESSAGE_IMPRINT:
				return MessageTag.BBB_CV_TSP_IRDOI;
			case COUNTER_SIGNED_SIGNATURE_VALUE:
				return MessageTag.BBB_CV_CS_CSPS;
			default:
				return MessageTag.BBB_CV_IRDOI;
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (digestMatcher.getType()) {
			case MESSAGE_IMPRINT:
				return MessageTag.BBB_CV_TSP_IRDOI_ANS;
			case COUNTER_SIGNED_SIGNATURE_VALUE:
				return MessageTag.BBB_CV_CS_CSPS_ANS;
			default:
				return MessageTag.BBB_CV_IRDOI_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.HASH_FAILURE;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (!DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType()) &&
				!DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
			String referenceName = Utils.isStringNotBlank(digestMatcher.getName()) ?
					digestMatcher.getName() : digestMatcher.getType().name();
			return i18nProvider.getMessage(MessageTag.REFERENCE, referenceName);
		}
		return null;
	}

}
