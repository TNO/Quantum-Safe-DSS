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
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustService.TrustServiceBuilder;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationElementType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationsType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifierType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifiersType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

/**
 * The class converts {@code TSPServiceType} to {@code TrustService}
 *
 */
public class TrustServiceConverter implements Function<TSPServiceType, TrustService> {

	/**
	 * Default constructor
	 */
	public TrustServiceConverter() {
		// emptyTrustServiceEquivalenceConverter
	}

	@Override
	public TrustService apply(TSPServiceType original) {
		TrustServiceBuilder trustServiceBuilder = new TrustService.TrustServiceBuilder();
		return trustServiceBuilder
				.setCertificates(extractCertificates(original.getServiceInformation()))
				.setStatusAndInformationExtensions(extractStatusAndHistory(original))
				.build();
	}

	private List<CertificateToken> extractCertificates(TSPServiceInformationType serviceInformation) {
		DigitalIdentityListTypeConverter converter = new DigitalIdentityListTypeConverter();
		DigitalIdentityListType serviceDigitalIdentityList = serviceInformation.getServiceDigitalIdentity();
		return Collections.unmodifiableList(converter.apply(serviceDigitalIdentityList));
	}

	private TimeDependentValues<TrustServiceStatusAndInformationExtensions> extractStatusAndHistory(TSPServiceType original) {
		MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<>();

		TSPServiceInformationType serviceInfo = original.getServiceInformation();

		InternationalNamesTypeConverter converter = new InternationalNamesTypeConverter();

		TrustServiceStatusAndInformationExtensionsBuilder statusBuilder = new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
		statusBuilder.setNames(converter.apply(serviceInfo.getServiceName()));
		statusBuilder.setType(serviceInfo.getServiceTypeIdentifier());
		statusBuilder.setStatus(serviceInfo.getServiceStatus());
		statusBuilder.setServiceSupplyPoints(getServiceSupplyPoints(serviceInfo.getServiceSupplyPoints()));

		parseExtensionsList(serviceInfo.getServiceInformationExtensions(), statusBuilder);

		Date nextEndDate = convertToDate(serviceInfo.getStatusStartingTime());
		statusBuilder.setStartDate(nextEndDate);
		statusHistoryList.addOldest(statusBuilder.build());

		if (original.getServiceHistory() != null && Utils.isCollectionNotEmpty(original.getServiceHistory().getServiceHistoryInstance())) {
			for (ServiceHistoryInstanceType serviceHistory : original.getServiceHistory().getServiceHistoryInstance()) {
				TrustServiceStatusAndInformationExtensionsBuilder statusHistoryBuilder = 
						new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
				statusHistoryBuilder.setNames(converter.apply(serviceHistory.getServiceName()));
				statusHistoryBuilder.setType(serviceHistory.getServiceTypeIdentifier());
				statusHistoryBuilder.setStatus(serviceHistory.getServiceStatus());

				parseExtensionsList(serviceHistory.getServiceInformationExtensions(), statusHistoryBuilder);

				statusHistoryBuilder.setEndDate(nextEndDate);
				nextEndDate = convertToDate(serviceHistory.getStatusStartingTime());
				statusHistoryBuilder.setStartDate(nextEndDate);
				statusHistoryList.addOldest(statusHistoryBuilder.build());
			}
		}

		return statusHistoryList;
	}

	private void parseExtensionsList(ExtensionsListType serviceInformationExtensions, TrustServiceStatusAndInformationExtensionsBuilder statusBuilder) {
		if (serviceInformationExtensions != null) {
			statusBuilder.setConditionsForQualifiers(extractConditionsForQualifiers(serviceInformationExtensions.getExtension()));
			statusBuilder.setAdditionalServiceInfoUris(extractAdditionalServiceInfoUris(serviceInformationExtensions.getExtension()));
			statusBuilder.setExpiredCertsRevocationInfo(extractExpiredCertsRevocationInfo(serviceInformationExtensions.getExtension()));
		}
	}

	@SuppressWarnings("rawtypes")
	private List<ConditionForQualifiers> extractConditionsForQualifiers(List<ExtensionType> extensions) {
		List<ConditionForQualifiers> conditionsForQualifiersList = new ArrayList<>();
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof QualificationsType) {
							List<ConditionForQualifiers> conditionForQualifiers =
									toConditionForQualificationsType((QualificationsType) jaxbElement.getValue());
							if (Utils.isCollectionNotEmpty(conditionForQualifiers)) {
								conditionsForQualifiersList.addAll(conditionForQualifiers);
							}
						}
					}
				}
			}
		}
		return conditionsForQualifiersList;
	}

	private List<ConditionForQualifiers> toConditionForQualificationsType(QualificationsType qt) {
		List<ConditionForQualifiers> conditionForQualifiers = new ArrayList<>();
		if ((qt != null) && Utils.isCollectionNotEmpty(qt.getQualificationElement())) {
			for (QualificationElementType qualificationElement : qt.getQualificationElement()) {
				ConditionForQualifiers condition = toConditionForQualifiers(qualificationElement);
				if (condition != null) {
					conditionForQualifiers.add(condition);
				}
			}
		}
		return conditionForQualifiers;
	}

	private ConditionForQualifiers toConditionForQualifiers(QualificationElementType qualificationElement) {
		List<String> qualifiers = extractQualifiers(qualificationElement);
		if (Utils.isCollectionNotEmpty(qualifiers)) {
			Condition condition = new CriteriaListConverter().apply(qualificationElement.getCriteriaList());
			return new ConditionForQualifiers(condition, Collections.unmodifiableList(qualifiers));
		}
		return null;
	}

	@SuppressWarnings("rawtypes")
	private List<String> extractAdditionalServiceInfoUris(List<ExtensionType> extensions) {
		List<String> additionalServiceInfos = new ArrayList<>();
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof AdditionalServiceInformationType) {
							AdditionalServiceInformationType additionalServiceInfo = (AdditionalServiceInformationType) objectValue;
							NonEmptyMultiLangURIType uri = additionalServiceInfo.getURI();
							if (uri != null && Utils.isStringNotBlank(uri.getValue())) {
								additionalServiceInfos.add(uri.getValue());
							}
						}
					}
				}
			}
		}
		return additionalServiceInfos;
	}

	@SuppressWarnings("rawtypes")
	private Date extractExpiredCertsRevocationInfo(List<ExtensionType> extensions) {
		for (ExtensionType extensionType : extensions) {
			List<Object> content = extensionType.getContent();
			if (Utils.isCollectionNotEmpty(content)) {
				for (Object object : content) {
					if (object instanceof JAXBElement) {
						JAXBElement jaxbElement = (JAXBElement) object;
						// TODO check tag name
						Object objectValue = jaxbElement.getValue();
						if (objectValue instanceof XMLGregorianCalendar) {
							return convertToDate((XMLGregorianCalendar) objectValue);
						}
					}
				}
			}
		}
		return null;
	}

	private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
		return gregorianCalendar.toGregorianCalendar().getTime();
	}

	private List<String> extractQualifiers(QualificationElementType qualificationElement) {
		List<String> qualifiers = new ArrayList<>();
		QualifiersType qualifiersType = qualificationElement.getQualifiers();
		if ((qualifiersType != null) && Utils.isCollectionNotEmpty(qualifiersType.getQualifier())) {
			for (QualifierType qualitierType : qualifiersType.getQualifier()) {
				qualifiers.add(qualitierType.getUri());
			}
		}
		return qualifiers;
	}

	private List<String> getServiceSupplyPoints(ServiceSupplyPointsType serviceSupplyPoints) {
		List<String> result = new ArrayList<>();
		if (serviceSupplyPoints != null && Utils.isCollectionNotEmpty(serviceSupplyPoints.getServiceSupplyPoint())) {
			for (AttributedNonEmptyURIType nonEmptyURI : serviceSupplyPoints.getServiceSupplyPoint()) {
				result.add(nonEmptyURI.getValue());
			}
		}
		return result;
	}

}
