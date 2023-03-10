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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.CertificateAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.RevocationAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.SatisfyingRevocationDataExistsCheck;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Performs Validation Time Sliding process
 */
public class ValidationTimeSliding extends Chain<XmlVTS> {

	/** Token to process */
	private final TokenProxy token;

	/** Validation time */
	private final Date currentTime;

	/** Map of all BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** Validation context */
	private final Context context;

	/** POE container */
	private final POEExtraction poe;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation time */
	private Date controlTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy}
	 * @param currentTime {@link Date}
	 * @param poe {@link POEExtraction}
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param context {@link Context}
	 * @param policy {@link ValidationPolicy}
	 */
	public ValidationTimeSliding(I18nProvider i18nProvider, TokenProxy token, Date currentTime, POEExtraction poe,
								 Map<String, XmlBasicBuildingBlocks> bbbs, Context context, ValidationPolicy policy) {
		super(i18nProvider, new XmlVTS());

		this.token = token;
		this.currentTime = currentTime;
		this.bbbs = bbbs;

		this.context = context;

		this.poe = poe;
		this.policy = policy;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VALIDATION_TIME_SLIDING;
	}

	@Override
	protected void initChain() {

		final XmlBasicBuildingBlocks tokenBBB = bbbs.get(token.getId());

		/*
		 * 5.6.2.2.4 Processing
		 * 
		 * 1) The building block shall initialize control-time to the current
		 * date/time.
		 * 
		 * NOTE 1: Control-time is an internal variable that is used within the
		 * algorithms and not part of the core results of the validation
		 * process.
		 */
		controlTime = currentTime;

		List<CertificateWrapper> certificateChain = token.getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {

			certificateChain = reduceChainUntilFirstTrustAnchor(certificateChain);

			/*
			 * 2) For each certificate in the chain starting from the first
			 * certificate (the certificate issued by the trust anchor):
			 */
			certificateChain = Utils.reverseList(certificateChain); // trusted_list -> ... -> signature

			ChainItem<XmlVTS> item = null;

			for (CertificateWrapper certificate : certificateChain) {
				if (certificate.isTrusted()) {
					continue;
				}

				/*
				 * a) The building block shall select revocation status information from
				 * the certificate validation data provided satisfying the following:
				 * 
				 * - the revocation status information is consistent with the rules conditioning its use
				 *   to check the revocation status of the considered certificate. In the case of a CRL,
				 *   it shall satisfy the checks specified in IETF RFC 5280 [1], clause 6.3.3 (b) to (l);
				 *   with the exception of the verification if the control-time is within the validity period
				 *   of the certificate of the issuer of the CRL; and
				 *
				 * - the issuance date of the revocation status information is before control time; and
				 *
				 * - the set of POEs contains a proof of existence of the certificate and
				 *   the revocation status information at (or before) control time.
				 * 
				 * If at least one revocation status information is selected,
				 * the building block shall go to the next step.
				 * If there is no such information, the building block shall return
				 * the indication INDETERMINATE with the sub indication NO_POE.
				 */

				final SubContext subContext = token.getSigningCertificate().getId().equals(certificate.getId()) ?
						SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
				final List<CertificateRevocationWrapper> certificateRevocationData = SubContext.SIGNING_CERT.equals(subContext) ?
						ValidationProcessUtils.getAcceptableRevocationDataForPSVIfExistOrReturnAll(token, certificate, bbbs, poe) : certificate.getCertificateRevocationData();

				CertificateRevocationSelector certificateRevocationSelector = new ValidationTimeSlidingCertificateRevocationSelector(
						i18nProvider, certificate, certificateRevocationData, controlTime, bbbs, tokenBBB.getId(), poe, policy);
				XmlCRS xmlCRS = certificateRevocationSelector.execute();
				result.getCRS().add(xmlCRS);

				if (item == null) {
					item = firstItem = satisfyingRevocationDataExists(xmlCRS, certificate, controlTime);
				} else {
					item = item.setNextItem(satisfyingRevocationDataExists(xmlCRS, certificate, controlTime));
				}
				
				CertificateRevocationWrapper latestCompliantRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();

				if (latestCompliantRevocation == null) {
					continue;
				}

				/*
				 * b) If the certificate is marked as revoked in any of the revocation status information
				 * found in the previous step, the building block shall perform the following steps:
				 *
				 * - select the revocation status information that has been issued the latest;
				 *
				 * - set control time to the revocation time whenever the validation policy requires
				 *   to use the shell model; or, when the validation policy requires to use the chain model and
				 *   the revocation reason is key compromise or unknown.
				 *
				 * - go to step d).
				 */
				if (latestCompliantRevocation.isRevoked()) {
					Model validationModel = policy.getValidationModel();
					RevocationReason revocationReason = latestCompliantRevocation.getReason();
					// NOTE : HYBRID model is treated as CHAIN for Signing Cert and as SHELL for CAs
					if (Model.SHELL.equals(validationModel)
							|| (Model.HYBRID.equals(validationModel) && SubContext.CA_CERTIFICATE.equals(subContext))
							|| RevocationReason.KEY_COMPROMISE.equals(revocationReason) || RevocationReason.UNSPECIFIED.equals(revocationReason)) {
						controlTime = latestCompliantRevocation.getRevocationDate();
					}

				/*
				 * c) If the certificate is not marked as revoked in all of the revocation status information
				 * found in step a), the building block shall select the revocation status information that
				 * has been issued the latest, run the Revocation Freshness Checker with that
				 * revocation information status information, the certificate for which the revocation status
				 * is being checked and the control time. If it returns FAILED, the building block shall set
				 * control time to the issuance time of the revocation status information.
				 * Otherwise, the building block shall not change the value of control time.
				 */
				} else {
					RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(
							i18nProvider, latestCompliantRevocation, controlTime, context, subContext, policy);
					XmlRFC execute = rfc.execute();
					if (execute.getConclusion() != null && Indication.FAILED.equals(execute.getConclusion().getIndication())) {
						controlTime = latestCompliantRevocation.getThisUpdate();
					}
				}

				/*
				 * d) The building block shall apply the cryptographic constraints to the certificate and
				 * the revocation status information against the control time. If the certificate
				 * (or the revocation status information) does not match these constraints, the building block shall
				 * set control time to the latest time up to which the listed algorithms were all considered reliable.
				 */
                Date cryptoNotAfterDate = null;
                
                XmlSAV certificateSAV = getCertificateCryptographicAcceptanceResult(certificate, controlTime);
				if (!isValidConclusion(certificateSAV.getConclusion())) {
					cryptoNotAfterDate = getCryptographicAlgorithmExpirationDateOrNull(certificateSAV);
                }
                XmlSAV revocationSAV = getRevocationCryptographicAcceptanceResult(latestCompliantRevocation, controlTime);
                if (!isValidConclusion(revocationSAV.getConclusion())) {
					Date revCryptoNotAfter = getCryptographicAlgorithmExpirationDateOrNull(revocationSAV);
                    if (cryptoNotAfterDate == null ||
							(revCryptoNotAfter != null && revCryptoNotAfter.before(cryptoNotAfterDate))) {
                        cryptoNotAfterDate = revCryptoNotAfter;
                    }
                }
                
                if (cryptoNotAfterDate != null && cryptoNotAfterDate.before(controlTime)) {
                    controlTime = cryptoNotAfterDate;
                }

                /*
                 * e) The building block shall continue with the next certificate in the chain or,
                 * if no further certificate exists, the building block shall return the status
                 * indication PASSED and the calculated control time.
                 */

			}
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime);
	}

	private List<CertificateWrapper> reduceChainUntilFirstTrustAnchor(List<CertificateWrapper> originalCertificateChain) {
		List<CertificateWrapper> result = new ArrayList<>();
		for (CertificateWrapper cert : originalCertificateChain) {
			result.add(cert);
			if (cert.isTrusted()) {
				break;
			}
		}
		return result;
	}

	private Date getCryptographicAlgorithmExpirationDateOrNull(XmlSAV sav) {
		if (sav.getCryptographicValidation() != null && sav.getCryptographicValidation().getAlgorithm() != null) {
			return sav.getCryptographicValidation().getNotAfter();
		}
		return null;
	}

	private ChainItem<XmlVTS> satisfyingRevocationDataExists(XmlCRS crsResult, CertificateWrapper certificateWrapper,
															 Date controlTime) {
		return new SatisfyingRevocationDataExistsCheck<>(i18nProvider, result, crsResult, certificateWrapper,
				controlTime, getFailLevelConstraint());
	}
	
    private XmlSAV getCertificateCryptographicAcceptanceResult(CertificateWrapper certificateWrapper, Date controlTime) {
		CertificateAcceptanceValidation cav = new CertificateAcceptanceValidation(i18nProvider, controlTime, certificateWrapper, policy);
        return cav.execute();
    }
    
    private XmlSAV getRevocationCryptographicAcceptanceResult(RevocationWrapper revocationWrapper, Date controlTime) {
        RevocationAcceptanceValidation rav = new RevocationAcceptanceValidation(i18nProvider, controlTime, revocationWrapper, policy);
        return rav.execute();
    }

}
