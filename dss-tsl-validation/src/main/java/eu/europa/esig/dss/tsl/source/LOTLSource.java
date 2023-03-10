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
package eu.europa.esig.dss.tsl.source;

import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

import java.util.function.Predicate;

/**
 * Represent a List of Trusted Lists source
 */
public class LOTLSource extends TLSource {

	/**
	 * Enable/disable pivot LOTL support
	 */
	private boolean pivotSupport = false;

	/**
	 * Enable/disable MRA (Mutual Recognition Agreement) LOTL support
	 */
	private boolean mraSupport = false;

	/**
	 * Predicate which filters the LOTL
	 * 
	 * Default : filter the XML European list of trusted list (LOTL)
	 */
	private Predicate<OtherTSLPointerType> lotlPredicate = TLPredicateFactory.createEULOTLPredicate();

	/**
	 * Predicate which filters the TLs
	 * 
	 * Default : filter all XML trusted lists (TL) for European countries
	 */
	private Predicate<OtherTSLPointerType> tlPredicate = TLPredicateFactory.createEUTLPredicate();

	/**
	 * Optional : Predicate which filters the URL where the provided signing
	 * certificates are defined
	 */
	private LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate;

	/**
	 * Default constructor instantiating object with minimal EU configuration
	 */
	public LOTLSource() {
		// empty
	}

	/**
	 * Gets if the LOTL configuration supports pivots
	 *
	 * @return TRUE if supports pivots, FALSE otherwise
	 */
	public boolean isPivotSupport() {
		return pivotSupport;
	}

	/**
	 * Sets if the LOTLSource shall support pivots
	 *
	 * @param pivotSupport if supports pivots
	 */
	public void setPivotSupport(boolean pivotSupport) {
		this.pivotSupport = pivotSupport;
	}

	/**
	 * Gets if the LOTL configuration supports MRA (Mutual Recognition Agreement).
	 *
	 * @return TRUE if supports MRA, FALSE otherwise
	 */
	public boolean isMraSupport() {
		return mraSupport;
	}

	/**
	 * Sets if the LOTL shall support MRA (Mutual Recognition Agreement) scheme defining trust service equivalence
	 * mapping between the LOTL and a third-country Trusted List
	 *
	 * Setting this condition to TRUE will allow to process LOTL containing pointers to a third-country trusted lists,
	 * including a special scheme for transition the qualification scope rules.
	 *
	 * Default : FALSE (LOTL MRA is not supported)
	 *
	 * @param mraSupport if LOTL shall support MRA
	 */
	public void setMraSupport(boolean mraSupport) {
		this.mraSupport = mraSupport;
	}

	/**
	 * Gets the LOTL filtering predicate
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<OtherTSLPointerType> getLotlPredicate() {
		return lotlPredicate;
	}

	/**
	 * Sets the LOTL filtering predicate
	 *
	 * @param lotlPredicate {@link Predicate}
	 */
	public void setLotlPredicate(Predicate<OtherTSLPointerType> lotlPredicate) {
		this.lotlPredicate = lotlPredicate;
	}

	/**
	 * Gets the TL filtering predicate
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<OtherTSLPointerType> getTlPredicate() {
		return tlPredicate;
	}

	/**
	 * Sets the TL filtering predicate
	 *
	 * @param tlPredicate {@link Predicate}
	 */
	public void setTlPredicate(Predicate<OtherTSLPointerType> tlPredicate) {
		this.tlPredicate = tlPredicate;
	}

	/**
	 * Gets the {@code LOTLSigningCertificatesAnnouncementSchemeInformationURI}
	 *
	 * @return {@link LOTLSigningCertificatesAnnouncementSchemeInformationURI}
	 */
	public LOTLSigningCertificatesAnnouncementSchemeInformationURI getSigningCertificatesAnnouncementPredicate() {
		return signingCertificatesAnnouncementPredicate;
	}

	/**
	 * Sets the {@code LOTLSigningCertificatesAnnouncementSchemeInformationURI}
	 *
	 * @param signingCertificatesAnnouncementPredicate {@link LOTLSigningCertificatesAnnouncementSchemeInformationURI}
	 */
	public void setSigningCertificatesAnnouncementPredicate(LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate) {
		this.signingCertificatesAnnouncementPredicate = signingCertificatesAnnouncementPredicate;
	}

}
