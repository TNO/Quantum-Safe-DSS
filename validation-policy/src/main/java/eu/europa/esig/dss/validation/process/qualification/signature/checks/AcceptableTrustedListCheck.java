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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Verifies whether the validation of aTrusted Lists is conclusive
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class AcceptableTrustedListCheck<T extends XmlConstraintsConclusion> extends AbstractTrustedListCheck<T> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param tlAnalysis {@link XmlTLAnalysis}
	 * @param constraint {@link LevelConstraint}
	 */
	public AcceptableTrustedListCheck(I18nProvider i18nProvider, T result, XmlTLAnalysis tlAnalysis,
									  LevelConstraint constraint) {
		super(i18nProvider, result, tlAnalysis, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT_ANS;
	}

}
