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
package eu.europa.esig.dss.enumerations;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains qualification statuses for TrustedServices
 *
 */
public enum ServiceQualification {

    /**
     * QCStatement ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"): to indicate that all certificates
     * identified by the applicable list of criteria are issued as qualified certificates.
     */
    QC_STATEMENT("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"),

    /**
     * NotQualified ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified"): to indicate that no
     * certificates
     * identified by the applicable list of criteria are to be considered as qualified certificates.
     */
    NOT_QUALIFIED("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified"),

    /**
     * QCWithSSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, have their
     * private key residing in an SSCD
     */
    QC_WITH_SSCD("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"),

    /**
     * QCWithQSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, have their
     * private key residing in a QSCD
     */
    QC_WITH_QSCD("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"),

    /**
     * QCNoSSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, do not have
     * their private key residing in an SSCD
     */
   QC_NO_SSCD("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD"),

    /**
     * QCNoQSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, do not have
     * their private key residing in a QSCD
     */
    QC_NO_QSCD("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD"),

    /**
     * QCSSCDStatusAsInCert ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert"): to indicate
     * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
     * qualified, do contain proper machine processable information about whether or not their private key residing in
     * an SSCD;
     */
    QC_SSCD_STATUS_AS_IN_CERT("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert"),

    /**
     * QCQSCDStatusAsInCert ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"): to indicate
     * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
     * qualified, do contain proper machine processable information about whether or not their private key residing in a
     * QSCD;
     */
    QC_QSCD_STATUS_AS_IN_CERT("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"),

    /**
     * QCQSCDManagedOnBehalf ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"): to indicate
     * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
     * qualified, have their private key residing in a QSCD for which the generation and management of that private key
     * is done by the qualified TSP on behalf of the entity whose identity is certified in the certificate;
     */
    QC_QSCD_MANAGED_ON_BEHALF("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"),

    /**
     * QCForLegalPerson("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"): to indicate that all
     * certificates identified by the applicable list of criteria, when they are claimed or stated as being qualified,
     * are issued to legal persons;
     */
    QC_FOR_LEGAL_PERSON("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"),

    /**
     * QCForESig ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
     * electronic signatures;
     */
    QC_FOR_ESIG("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"),

    /**
     * QCForESeal ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
     * electronic seals;
     */
    QC_FOR_ESEAL("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"),

    /**
     * QCForWSA ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"): to indicate that all certificates
     * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
     * web site authentication;
     */
    QC_FOR_WSA("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA");

    /** Defines URI of the enumeration */
    private final String uri;

    /**
     * Empty constructor
     */
    ServiceQualification(final String uri) {
        this.uri = uri;
    }

    /**
     * Gets URI of the AdditionalServiceInformation
     *
     * @return {@link String}
     */
    public String getUri() {
        return uri;
    }

    /**
     * This method returns {@code ServiceQualification} for the given {@code uri}
     *
     * @param uri {@link String} to get {@link ServiceQualification} for
     * @return {@link ServiceQualification} if exists, null otherwise
     */
    public static ServiceQualification getByUri(String uri) {
        if (uri != null) {
            for (ServiceQualification serviceQualification : ServiceQualification.values()) {
                if (uri.equals(serviceQualification.getUri())) {
                    return serviceQualification;
                }
            }
        }
        return null;
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCStatement' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCStatement' identifier, FALSE otherwise
     */
    public static boolean isQcStatement(List<String> qualifiers) {
        return listContains(qualifiers, QC_STATEMENT);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'NotQualified' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'NotQualified' identifier, FALSE otherwise
     */
    public static boolean isNotQualified(List<String> qualifiers) {
        return listContains(qualifiers, NOT_QUALIFIED);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCNoQSCD' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains 'QCNoQSCD' identifier, FALSE otherwise
     */
    public static boolean isQcNoQSCD(List<String> qualifiers) {
        return listContains(qualifiers, QC_NO_QSCD);
    }
    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCNoSSCD' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains 'QCNoSSCD' identifier, FALSE otherwise
     */
    public static boolean isQcNoSSCD(List<String> qualifiers) {
        return listContains(qualifiers, QC_NO_SSCD);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCForLegalPerson' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCForLegalPerson' identifier, FALSE otherwise
     */
    public static boolean isQcForLegalPerson(List<String> qualifiers) {
        return listContains(qualifiers, QC_FOR_LEGAL_PERSON);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCQSCDStatusAsInCert' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains 'QCQSCDStatusAsInCert' identifier, FALSE otherwise
     */
    public static boolean isQcQSCDStatusAsInCert(List<String> qualifiers) {
        return listContains(qualifiers, QC_QSCD_STATUS_AS_IN_CERT);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCSSCDStatusAsInCert' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains QCSSCDStatusAsInCert' identifier, FALSE otherwise
     */
    public static boolean isQcSSCDStatusAsInCert(List<String> qualifiers) {
        return listContains(qualifiers, QC_SSCD_STATUS_AS_IN_CERT);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCQSCDManagedOnBehalf' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCQSCDManagedOnBehalf' identifier, FALSE otherwise
     */
    public static boolean isQcQSCDManagedOnBehalf(List<String> qualifiers) {
        return listContains(qualifiers, QC_QSCD_MANAGED_ON_BEHALF);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCWithQSCD' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains 'QCWithQSCD' identifier, FALSE otherwise
     */
    public static boolean isQcWithQSCD(List<String> qualifiers) {
        return listContains(qualifiers, QC_WITH_QSCD);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCWithSSCD' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains 'QCWithQSCD' identifier, FALSE otherwise
     */
    public static boolean isQcWithSSCD(List<String> qualifiers) {
        return listContains(qualifiers, QC_WITH_SSCD);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCForESig' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCForESig' identifier, FALSE otherwise
     */
    public static boolean isQcForEsig(List<String> qualifiers) {
        return listContains(qualifiers, QC_FOR_ESIG);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCForESeal' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCForESeal' identifier, FALSE otherwise
     */
    public static boolean isQcForEseal(List<String> qualifiers) {
        return listContains(qualifiers, QC_FOR_ESEAL);
    }

    /**
     * Gets whether the list of TrustedService qualifiers contains 'QCForWSA' identifier
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return TRUE if the list of qualifiers contains the 'QCForWSA' identifier, FALSE otherwise
     */
    public static boolean isQcForWSA(List<String> qualifiers) {
        return listContains(qualifiers, QC_FOR_WSA);
    }

    /**
     * Filters qualifiers containing the usage type identifiers (i.e. 'QCForESig', 'QCForESeal' or 'QCForWSA')
     *
     * @param qualifiers list of {@link String} qualifiers extracted from a TrustedService
     * @return filtered list of qualifiers containing the usage type identifiers
     */
    public static List<String> getUsageQualifiers(List<String> qualifiers) {
        List<String> filteredQualifiers = new ArrayList<>();
        if (qualifiers != null && !qualifiers.isEmpty()) {
            if (qualifiers.contains(QC_FOR_ESIG.getUri())) {
                filteredQualifiers.add(QC_FOR_ESIG.getUri());
            }
            if (qualifiers.contains(QC_FOR_ESEAL.getUri())) {
                filteredQualifiers.add(QC_FOR_ESEAL.getUri());
            }
            if (qualifiers.contains(QC_FOR_WSA.getUri())) {
                filteredQualifiers.add(QC_FOR_WSA.getUri());
            }
        }
        return filteredQualifiers;
    }

    private static boolean listContains(List<String> qualifiers, ServiceQualification... expecteds) {
        if (qualifiers != null && !qualifiers.isEmpty()) {
            for (ServiceQualification expected : expecteds) {
                if (qualifiers.contains(expected.getUri())) {
                    return true;
                }
            }
        }
        return false;
    }

}
