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
package eu.europa.esig.dss.cades.validation.timestamp;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampMessageDigestBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

/**
 * Builds timestamped data binaries for a CAdES signature
 */
public class CAdESTimestampMessageDigestBuilder implements TimestampMessageDigestBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampMessageDigestBuilder.class);

	/** The error message to be thrown in case of a message-imprint build error */
	private static final String MESSAGE_IMPRINT_ERROR = "Unable to compute message-imprint for TimestampToken with Id '{}'. Reason : {}";

	/** The CMS SignedData */
	private final CMSSignedData cmsSignedData;

	/** The SignerInformation of the related signature */
	private final SignerInformation signerInformation;

	/** The list of detached documents */
	private final List<DSSDocument> detachedDocuments;

	/** The instance of CadesLevelBaselineLTATimestampExtractor */
	private final CadesLevelBaselineLTATimestampExtractor timestampExtractor;

	/** The digest algorithm to be used for message-imprint digest computation */
	private DigestAlgorithm digestAlgorithm;

	/** Timestamp token to compute message-digest for */
	private TimestampToken timestampToken;

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature}
	 *
	 * @param signature {@link CAdESSignature} to create timestamps for
	 * @param certificateSource {@link ListCertificateSource} merged certificate source of the signature
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-imprint digest computation
	 */
	public CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											  final ListCertificateSource certificateSource,
											  final DigestAlgorithm digestAlgorithm) {
		this(signature, certificateSource);
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature}
	 *
	 * @param signature {@link CAdESSignature} containing timestamps
	 * @param certificateSource {@link ListCertificateSource} merged certificate source of the signature
	 * @param timestampToken {@link TimestampToken} to compute message-digest for
	 */
	public CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											  final ListCertificateSource certificateSource,
											  final TimestampToken timestampToken) {
		this(signature, certificateSource);
		Objects.requireNonNull(timestampToken, "TimestampToken cannot be null!");
		this.timestampToken = timestampToken;
		this.digestAlgorithm = timestampToken.getDigestAlgorithm();
	}

	/**
	 * The default constructor
	 *
	 * @param signature {@link CAdESSignature} containing timestamps
	 * @param certificateSource {@link ListCertificateSource} merged certificate source of the signature
	 */
	private CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											   final ListCertificateSource certificateSource) {
		Objects.requireNonNull(signature, "Signature cannot be null!");
		Objects.requireNonNull(certificateSource, "ListCertificateSource cannot be null!");
		this.cmsSignedData = signature.getCmsSignedData();
		this.signerInformation = signature.getSignerInformation();
		this.detachedDocuments = signature.getDetachedContents();
		this.timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(
				cmsSignedData, certificateSource.getAllCertificateTokens());
	}

	@Override
	public DSSMessageDigest getContentTimestampMessageDigest() {
		return getOriginalDocumentDigest();
	}

	@Override
	public DSSMessageDigest getSignatureTimestampMessageDigest() {
		byte[] signature = signerInformation.getSignature();
		return new DSSMessageDigest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, signature));
	}

	@Override
	public DSSMessageDigest getTimestampX1MessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			digestCalculator.update(signerInformation.getSignature());
			// We don't include the outer SEQUENCE, only the attrType and
			// attrValues as stated by the TS Â§6.3.5, NOTE 2

			final Attribute attribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_signatureTimeStampToken);
			if (attribute != null) {
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
			}
			// Method is common to Type 1 and Type 2
			writeTimestampX2MessageDigest(digestCalculator);
			return digestCalculator.getMessageDigest();

		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage(), e);
			} else {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage());
			}
		}
		return null;
	}

	@Override
	public DSSMessageDigest getTimestampX2MessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			writeTimestampX2MessageDigest(digestCalculator);
			return digestCalculator.getMessageDigest();

		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage(), e);
			} else {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage());
			}
		}
		return null;
	}

	private void writeTimestampX2MessageDigest(DSSMessageDigestCalculator digestCalculator) {
		// Those are common to Type 1 and Type 2
		final Attribute certAttribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_certificateRefs);
		final Attribute revAttribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_revocationRefs);
		if (certAttribute != null) {
			digestCalculator.update(DSSASN1Utils.getDEREncoded(certAttribute.getAttrType()));
			digestCalculator.update(DSSASN1Utils.getDEREncoded(certAttribute.getAttrValues()));
		}
		if (revAttribute != null) {
			digestCalculator.update(DSSASN1Utils.getDEREncoded(revAttribute.getAttrType()));
			digestCalculator.update(DSSASN1Utils.getDEREncoded(revAttribute.getAttrValues()));
		}
	}

	@Override
	public DSSMessageDigest getArchiveTimestampMessageDigest() {
		// V3 is used by default
		final ArchiveTimestampType archiveTimestampType = timestampToken != null ?
				timestampToken.getArchiveTimestampType() : ArchiveTimestampType.CAdES_V3;

		DSSMessageDigest messageDigest;
		switch (archiveTimestampType) {
		case CAdES_V2:
			/**
			 * There is a difference between message imprint calculation in ETSI TS 101 733 version 1.8.3 and version 2.2.1.
			 * So we first check the message imprint according to 2.2.1 version and then if it fails get the message imprint
			 * data for the 1.8.3 version message imprint calculation. 
			 */
			messageDigest = getArchiveTimestampDataV2( true);
			if (!timestampToken.matchData(messageDigest, true)) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Unable to match message imprint for an Archive TimestampToken V2 with Id '{}' "
							+ "by including unsigned attribute tags and length, try to compute the data without...", timestampToken.getDSSIdAsString());
				}
				messageDigest = getArchiveTimestampDataV2(false);
			}
			break;
		case CAdES_V3:
			messageDigest = getArchiveTimestampDataV3();
			break;
		default:
			throw new DSSException("Unsupported ArchiveTimestampType " + archiveTimestampType);
		}

		return messageDigest;
	}

	private DSSMessageDigest getArchiveTimestampDataV3() throws DSSException {
		final Attribute atsHashIndexAttribute = timestampExtractor.getVerifiedAtsHashIndex(signerInformation, timestampToken);
		final DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			return timestampExtractor.getArchiveTimestampV3MessageImprint(
					signerInformation, atsHashIndexAttribute, originalDocument, digestAlgorithm);
		} else {
			LOG.error("The original document is not found for TimestampToken with Id '{}'! "
					+ "Unable to compute message imprint.", timestampToken.getDSSIdAsString());
			return DSSMessageDigest.createEmptyDigest();
		}
	}
	
	private DSSMessageDigest getOriginalDocumentDigest() {
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			final byte[] digest = Utils.fromBase64(originalDocument.getDigest(digestAlgorithm));
			return new DSSMessageDigest(digestAlgorithm, digest);
		} else {
			LOG.error("The original document is not found for TimestampToken with Id '{}'! "
					+ "Unable to compute message imprint.", timestampToken.getDSSIdAsString());
			return DSSMessageDigest.createEmptyDigest();
		}
	}
	
	/**
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to simultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 * 
	 * According to RFC 5652 it is possible to use DER or BER encoding for SignedData structure.
	 * The exception is the signed attributes attribute and authenticated attributes which
	 * have to be DER encoded. 
	 *
	 * @param includeUnsignedAttrsTagAndLength decides whether the tag and length octets are included.
	 * @return {@link DSSMessageDigest} archiveTimestampDataV2 message-imprint digest
	 */
	private DSSMessageDigest getArchiveTimestampDataV2(boolean includeUnsignedAttrsTagAndLength) throws DSSException {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
			final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
			
			byte[] bytes = getContentInfoBytes(signedData);
			digestCalculator.update(bytes);
			
			if (CMSUtils.isDetachedSignature(cmsSignedData)) {
				bytes = getOriginalDocumentBinaries();
				if (bytes == null) {
					LOG.warn("The detached content is not provided for a TimestampToken with Id '{}'. "
							+ "Not possible to compute message imprint!", timestampToken.getDSSIdAsString());
					return DSSMessageDigest.createEmptyDigest();
				}
				digestCalculator.update(bytes);
			}
			
			bytes = getCertificateDataBytes(signedData);
			if (Utils.isArrayNotEmpty(bytes)) {
				digestCalculator.update(bytes);
			}
			
			bytes = getCRLDataBytes(signedData);
			if (Utils.isArrayNotEmpty(bytes)) {
				digestCalculator.update(bytes);
			}

			writeSignerInfoBytes(digestCalculator, includeUnsignedAttrsTagAndLength);

			return digestCalculator.getMessageDigest();

		} catch (Exception e) {
			// When error in computing or in format the algorithm just continues.
			LOG.error("An error in computing of message-imprint for a TimestampToken with Id : {}. Reason : {}",
					timestampToken.getDSSIdAsString(), e.getMessage(), e);
			return null;
		}
	}
	
	private byte[] getContentInfoBytes(final SignedData signedData) {
		final ContentInfo content = signedData.getEncapContentInfo();
		byte[] contentInfoBytes;
		if (content.getContent() instanceof BEROctetString) {
			contentInfoBytes = DSSASN1Utils.getBEREncoded(content);
		} else {
			contentInfoBytes = DSSASN1Utils.getDEREncoded(content);
		}
		if (LOG.isTraceEnabled()) {
			LOG.trace("Content Info: {}", DSSUtils.toHex(contentInfoBytes));
		}
		return contentInfoBytes;
	}
	
	private byte[] getOriginalDocumentBinaries() {
		/*
		 * Detached signatures have either no encapContentInfo in signedData, or it
		 * exists but has no eContent
		 */
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			return DSSUtils.toByteArray(getOriginalDocument());
		}
		return null;
	}
	
	private byte[] getCertificateDataBytes(final SignedData signedData) throws IOException {
		byte[] certificatesBytes = null;
		
		final ASN1Set certificates = signedData.getCertificates();
		if (certificates != null) {
			/*
			 * In order to calculate correct message imprint it is important
			 * to use the correct encoding.
			 */
			if (certificates instanceof BERSet) {
				certificatesBytes = new BERTaggedObject(false, 0, new BERSequence(certificates.toArray())).getEncoded();
			} else {
				certificatesBytes = new DERTaggedObject(false, 0, new DERSequence(certificates.toArray())).getEncoded();
			}
			
			if (LOG.isTraceEnabled()) {
				LOG.trace("Certificates: {}", DSSUtils.toHex(certificatesBytes));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Certificates are not present in the SignedData.");
		}
		return certificatesBytes;
	}
	
	private byte[] getCRLDataBytes(final SignedData signedData) throws IOException {
		byte[] crlBytes = null;
		
		final ASN1Set crLs = signedData.getCRLs();
		if (crLs != null) {
			
			if (signedData.getCRLs() instanceof BERSet) {
				crlBytes = new BERTaggedObject(false, 1, new BERSequence(crLs.toArray())).getEncoded();
			} else {
				crlBytes = new DERTaggedObject(false, 1, new DERSequence(crLs.toArray())).getEncoded();
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("CRLs: {}", DSSUtils.toHex(crlBytes));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("CRLs are not present in the SignedData.");
		}
		return crlBytes;
	}
	
	private void writeSignerInfoBytes(final DSSMessageDigestCalculator digestCalculator, boolean includeUnsignedAttrsTagAndLength) {
		final SignerInfo signerInfo = signerInformation.toASN1Structure();
		final ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
		final ASN1Sequence filteredUnauthenticatedAttributes = filterUnauthenticatedAttributes(unauthenticatedAttributes, timestampToken);
		final ASN1Sequence asn1Object = getSignerInfoEncoded(signerInfo, filteredUnauthenticatedAttributes, includeUnsignedAttrsTagAndLength);
		for (int ii = 0; ii < asn1Object.size(); ii++) {
			final byte[] signerInfoBytes = DSSASN1Utils.getDEREncoded(asn1Object.getObjectAt(ii).toASN1Primitive());
			if (LOG.isTraceEnabled()) {
				LOG.trace("SignerInfoBytes: {}", DSSUtils.toHex(signerInfoBytes));
			}
			digestCalculator.update(signerInfoBytes);
		}
	}

	/**
	 * Remove any archive-timestamp-v2/3 attribute added after the
	 * timestampToken
	 */
	private ASN1Sequence filterUnauthenticatedAttributes(ASN1Set unauthenticatedAttributes, TimestampToken timestampToken) {
		ASN1EncodableVector result = new ASN1EncodableVector();
		for (int ii = 0; ii < unauthenticatedAttributes.size(); ii++) {

			final Attribute attribute = Attribute.getInstance(unauthenticatedAttributes.getObjectAt(ii));
			final ASN1ObjectIdentifier attrType = attribute.getAttrType();
			if (id_aa_ets_archiveTimestampV2.equals(attrType) || id_aa_ets_archiveTimestampV3.equals(attrType)) {
				try {

					TimeStampToken token = DSSASN1Utils.getTimeStampToken(attribute);
					if (token == null || !token.getTimeStampInfo().getGenTime().before(timestampToken.getGenerationTime())) {
						continue;
					}

				} catch (Exception e) {
					throw new DSSException(String.format("Unexpected error occurred on reading unsigned properties : %s",
							e.getMessage()), e);
				}
			}
			result.add(unauthenticatedAttributes.getObjectAt(ii));
		}
		return new DERSequence(result);
	}

	/**
	 * Copied from org.bouncycastle.asn1.cms.SignerInfo#toASN1Object() and
	 * adapted to be able to use the custom unauthenticatedAttributes
	 * 
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to imultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 *
	 * @param signerInfo {@link SignerInfo}
	 * @param unauthenticatedAttributes {@link ASN1Sequence}
	 * @param includeUnsignedAttrsTagAndLength decides whether the tag and length octets are included
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getSignerInfoEncoded(final SignerInfo signerInfo, final ASN1Sequence unauthenticatedAttributes,
											  final boolean includeUnsignedAttrsTagAndLength) {

		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(signerInfo.getVersion());
		v.add(signerInfo.getSID());
		v.add(signerInfo.getDigestAlgorithm());

		final DERTaggedObject signedAttributes = CMSUtils.getDERSignedAttributes(signerInformation);
		if (signedAttributes != null) {
			v.add(signedAttributes);
		}

		v.add(signerInfo.getDigestEncryptionAlgorithm());
		v.add(signerInfo.getEncryptedDigest());

		if (unauthenticatedAttributes != null) {
			if (includeUnsignedAttrsTagAndLength) {
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			} else {
				for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
					v.add(unauthenticatedAttributes.getObjectAt(i));
				}
			}
		}
		
		return new DERSequence(v);
	}
	
	private DSSDocument getOriginalDocument() {
		try {
			return CMSUtils.getOriginalDocument(cmsSignedData, detachedDocuments);
		} catch (DSSException e) {
			LOG.error("Cannot extract original document! Reason : {}", e.getMessage());
			return null;
		}
	}

}
