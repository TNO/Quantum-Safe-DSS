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
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.xmldsig.XSDAbstractUtils;

import java.io.Serializable;

/**
 * Contains a list of useful XAdES XPaths
 */
public interface XAdESPaths extends Serializable {

	/**
	 * Gets the current namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	DSSNamespace getNamespace();

	/**
	 * Gets signed properties reference URI
	 *
	 * @return {@link String}
	 */
	String getSignedPropertiesUri();

	/**
	 * Gets counter signature reference URI
	 *
	 * @return {@link String}
	 */
	String getCounterSignatureUri();

	// ----------------------- From Object

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties"
	 *
	 * @return {@link String} path
	 */
	String getQualifyingPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties"
	 *
	 * @return {@link String} path
	 */
	String getSignedPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties"
	 *
	 * @return {@link String} path
	 */
	String getSignedSignaturePropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime"
	 *
	 * @return {@link String} path
	 */
	String getSigningTimePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate"
	 *
	 * @return {@link String} path
	 */
	String getSigningCertificatePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getSigningCertificateChildren();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2"
	 *
	 * @return {@link String} path
	 */
	String getSigningCertificateV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getSigningCertificateV2Children();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignatureProductionPlace"
	 *
	 * @return {@link String} path
	 */
	String getSignatureProductionPlacePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignatureProductionPlaceV2"
	 *
	 * @return {@link String} path
	 */
	String getSignatureProductionPlaceV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignaturePolicyIdentifier"
	 *
	 * @return {@link String} path
	 */
	String getSignaturePolicyIdentifierPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole"
	 *
	 * @return {@link String} path
	 */
	String getSignerRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole"
	 *
	 * @return {@link String} path
	 */
	String getClaimedRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:SignedAssertions/xades:SignedAssertion"
	 *
	 * @return {@link String} path
	 */
	String getSignedAssertionPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2"
	 *
	 * @return {@link String} path
	 */
	String getSignerRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole"
	 *
	 * @return {@link String} path
	 */
	String getClaimedRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:CertifiedRoles/xades:CertifiedRole"
	 *
	 * @return {@link String} path
	 */
	String getCertifiedRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2/xades:CertifiedRoles/xades:CertifiedRole"
	 *
	 * @return {@link String} path
	 */
	String getCertifiedRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"
	 *
	 * @return {@link String} path
	 */
	String getSignedDataObjectPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat"
	 *
	 * @return {@link String} path
	 */
	String getDataObjectFormat();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:MimeType"
	 *
	 * @return {@link String} path
	 */
	String getDataObjectFormatMimeType();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:ObjectIdentifier"
	 *
	 * @return {@link String} path
	 */
	String getDataObjectFormatObjectIdentifier();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:CommitmentTypeIndication"
	 *
	 * @return {@link String} path
	 */
	String getCommitmentTypeIndicationPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties"
	 *
	 * @return {@link String} path
	 */
	String getUnsignedPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
	 *
	 * @return {@link String} path
	 */
	String getUnsignedSignaturePropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CounterSignature"
	 *
	 * @return {@link String} path
	 */
	String getCounterSignaturePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeRevocationRefs"
	 *
	 * @return {@link String} path
	 */
	String getAttributeRevocationRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
	 *
	 * @return {@link String} path
	 */
	String getCompleteRevocationRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs"
	 *
	 * @return {@link String} path
	 */
	String getCompleteCertificateRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs/xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getCompleteCertificateRefsCertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:CompleteCertificateRefsV2"
	 *
	 * @return {@link String} path
	 */
	String getCompleteCertificateRefsV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:CompleteCertificateRefsV2/xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getCompleteCertificateRefsV2CertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeCertificateRefs"
	 *
	 * @return {@link String} path
	 */
	String getAttributeCertificateRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeCertificateRefs/xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getAttributeCertificateRefsCertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AttributeCertificateRefsV2"
	 *
	 * @return {@link String} path
	 */
	String getAttributeCertificateRefsV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AttributeCertificateRefsV2/xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getAttributeCertificateRefsV2CertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CertificateValues"
	 *
	 * @return {@link String} path
	 */
	String getCertificateValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RevocationValues"
	 *
	 * @return {@link String} path
	 */
	String getRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeRevocationValues"
	 *
	 * @return {@link String} path
	 */
	String getAttributeRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SigAndRefsTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	String getEncapsulatedCertificateValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttrAuthoritiesCertValues"
	 *
	 * @return {@link String} path
	 */
	String getAttrAuthoritiesCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttrAuthoritiesCertValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	String getEncapsulatedAttrAuthoritiesCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:TimeStampValidationData/xades:CertificateValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	String getEncapsulatedTimeStampValidationDataCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:TimeStampValidationData/xades:RevocationValues"
	 *
	 * @return {@link String} path
	 */
	String getTimeStampValidationDataRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp"
	 *
	 * @return {@link String} path
	 */
	String getSignatureTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SigAndRefsTimeStamp"
	 *
	 * @return {@link String} path
	 */
	String getSigAndRefsTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SigAndRefsTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	String getSigAndRefsTimestampV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RefsOnlyTimeStamp"
	 *
	 * @return {@link String} path
	 */
	String getRefsOnlyTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:RefsOnlyTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	String getRefsOnlyTimestampV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp"
	 *
	 * @return {@link String} path
	 */
	String getArchiveTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:TimeStampValidationData"
	 *
	 * @return {@link String} path
	 */
	String getTimestampValidationDataPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SignaturePolicyStore"
	 *
	 * @return {@link String} path
	 */
	String getSignaturePolicyStorePath();

	// ----------------

	/**
	 * Gets path "./xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCRLValuesChildren();

	/**
	 * Gets path "./xades:CRLRefs/xades:CRLRef"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCRLRefsChildren();

	/**
	 * Gets path "./xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPValuesChildren();

	/**
	 * Gets path "./xades:OCSPRefs/xades:OCSPRef"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPRefsChildren();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderID"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPRefResponderID();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderI/xades:ByName"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPRefResponderIDByName();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderI/xades:ByKey"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPRefResponderIDByKey();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ProducedAt"
	 *
	 * @return {@link String} path
	 */
	String getCurrentOCSPRefProducedAt();

	/**
	 * Gets path "./xades:DigestAlgAndValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentDigestAlgAndValue();

	/**
	 * Gets path "./xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCertRefsCertChildren();

	/**
	 * Gets path "./xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCertRefs141CertChildren();

	/**
	 * Gets path "./xades:Cert"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCertChildren();

	/**
	 * Gets path "./xades:CertDigest"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCertDigest();

	/**
	 * Gets path "./xades:EncapsulatedTimeStamp"
	 *
	 * @return {@link String} path
	 */
	String getCurrentEncapsulatedTimestamp();

	/**
	 * Gets path "./xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	String getCurrentEncapsulatedCertificate();

	/**
	 * Gets path "./xades:CertificateValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCertificateValuesEncapsulatedCertificate();

	/**
	 * Gets path "./xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentRevocationValuesEncapsulatedOCSPValue();

	/**
	 * Gets path "./xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentEncapsulatedOCSPValue();

	/**
	 * Gets path "./xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentRevocationValuesEncapsulatedCRLValue();

	/**
	 * Gets path "./xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	String getCurrentEncapsulatedCRLValue();

	/**
	 * Gets path "./xades:IssuerSerial/xades:X509IssuerName"
	 *
	 * @return {@link String} path
	 */
	String getCurrentIssuerSerialIssuerNamePath();

	/**
	 * Gets path "./xades:IssuerSerial/xades:X509SerialNumber"
	 *
	 * @return {@link String} path
	 */
	String getCurrentIssuerSerialSerialNumberPath();

	/**
	 * Gets path "./xades:IssuerSerialV2"
	 *
	 * @return {@link String} path
	 */
	String getCurrentIssuerSerialV2Path();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCommitmentIdentifierPath();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:Description"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCommitmentDescriptionPath();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCommitmentDocumentationReferencesPath();

	/**
	 * Gets path "./xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	String getCurrentDocumentationReference();

	/**
	 * Gets path "./xades:Description"
	 *
	 * @return {@link String} path
	 */
	String getCurrentDescription();

	/**
	 * Gets path "./xades:ObjectIdentifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentObjectIdentifier();

	/**
	 * Gets path "./xades:ObjectReference"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCommitmentObjectReferencesPath();

	/**
	 * Gets path "./xades:AllSignedDataObjects"
	 *
	 * @return {@link String} path
	 */
	String getCurrentCommitmentAllSignedDataObjectsPath();

	/**
	 * Gets path "./xades:MimeType"
	 *
	 * @return {@link String} path
	 */
	String getCurrentMimeType();

	/**
	 * Gets path "./xades:Encoding"
	 *
	 * @return {@link String} path
	 */
	String getCurrentEncoding();

	// --------------------------- Policy

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyId();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyHash"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyDigestAlgAndValue();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPURI"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicySPURI();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPUserNotice"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicySPUserNotice();

	/**
	 * Gets path "./xades:NoticeRef/xades:Organization"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPUserNoticeNoticeRefOrganization();

	/**
	 * Gets path "./xades:NoticeRef/xades:NoticeNumbers"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPUserNoticeNoticeRefNoticeNumbers();

	/**
	 * Gets path "./xades:NoticeRef/xades:NoticeNumbers"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPUserNoticeExplicitText();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades141:SPDocSpecification"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicySPDocSpecification();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades141:SPDocSpecification/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicySPDocSpecificationIdentifier();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Description"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyDescription();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyDocumentationReferences();

	/**
	 * Gets path "./xades:SignaturePolicyImplied"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyImplied();

	/**
	 * Gets path "./xades:SignaturePolicyId/ds:Transforms"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyTransforms();

	/**
	 * Gets path "./xades:SignaturePolicyId/ds:SigPolicyQualifiers"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyQualifiers();

	/**
	 * Gets path "./xades:Include"
	 *
	 * @return {@link String} path
	 */
	String getCurrentInclude();

	/**
	 * Gets path "./xades:QualifyingProperties"
	 *
	 * @return {@link String} path
	 */
	String getCurrentQualifyingPropertiesPath();

	// --------------------------- Signature Policy Store

	/**
	 * Gets path "./xades141:SPDocSpecification"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPDocSpecification();

	/**
	 * Gets path "./xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentIdentifier();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPDocSpecificationIdentifier();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:Description"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPDocSpecificationDescription();

	/**
	 * Gets path ".xades:DocumentationReferences/xades:DocumentationReference"
	 *
	 * @return {@link String} path
	 */
	String getCurrentDocumentationReferenceElements();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:DocumentationReferences/xades:DocumentationReference"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSPDocSpecificationDocumentationReferenceElements();

	/**
	 * Gets path "./xades141:SignaturePolicyDocument"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSignaturePolicyDocument();

	/**
	 * Gets path "./xades141:SigPolDocLocalURI"
	 *
	 * @return {@link String} path
	 */
	String getCurrentSigPolDocLocalURI();

	/**
	 * Gets the XSD Utils
	 *
	 * @return {@link XSDAbstractUtils}
	 */
	XSDAbstractUtils getXSDUtils();

}
