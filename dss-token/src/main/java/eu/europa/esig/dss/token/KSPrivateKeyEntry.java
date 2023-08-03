/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper of a PrivateKeyEntry coming from a KeyStore.
 */
public class KSPrivateKeyEntry implements DSSPrivateKeyEntry {

    /**
     * The key's alias
     */
    private final String alias;

    /**
     * The certificate
     */
    private final CertificateToken certificate;

    /**
     * The corresponding certificate chain
     */
    private final CertificateToken[] certificateChain;

    /**
     * The private key
     */
    private final PrivateKey privateKey;

    private final EncryptionAlgorithm encryptionAlgorithm;

    /**
     * The default constructor for KSPrivateKeyEntry.
     *
     * @param alias           the given alias
     * @param privateKeyEntry the keystore private key entry
     */
    public KSPrivateKeyEntry(final String alias, final PrivateKeyEntry privateKeyEntry) {
//		this.alias = alias;
//		certificate = new CertificateToken((X509Certificate) privateKeyEntry.getCertificate());
//		final List<CertificateToken> x509CertificateList = new ArrayList<>();
//		final Certificate[] simpleCertificateChain = privateKeyEntry.getCertificateChain();
//		for (final Certificate currentCertificate : simpleCertificateChain) {
//			x509CertificateList.add(new CertificateToken((X509Certificate) currentCertificate));
//		}
//		final CertificateToken[] certificateChainArray = new CertificateToken[x509CertificateList.size()];
//		certificateChain = x509CertificateList.toArray(certificateChainArray);
//		privateKey = privateKeyEntry.getPrivateKey();
//		this.encryptionAlgorithm = deriveEncryptionAlgorithm();
        this(alias, privateKeyEntry.getPrivateKey(), (X509Certificate) privateKeyEntry.getCertificate(), privateKeyEntry.getCertificateChain(), EncryptionAlgorithm.forKey(privateKeyEntry.getCertificate().getPublicKey()));
    }

    public KSPrivateKeyEntry(final String alias, final PrivateKeyEntry privateKeyEntry, EncryptionAlgorithm encryptionAlgorithm) {
//		this.alias = alias;
//		certificate = new CertificateToken((X509Certificate) privateKeyEntry.getCertificate());
//		final List<CertificateToken> x509CertificateList = new ArrayList<>();
//		final Certificate[] simpleCertificateChain = privateKeyEntry.getCertificateChain();
//		for (final Certificate currentCertificate : simpleCertificateChain) {
//			x509CertificateList.add(new CertificateToken((X509Certificate) currentCertificate));
//		}
//		final CertificateToken[] certificateChainArray = new CertificateToken[x509CertificateList.size()];
//		certificateChain = x509CertificateList.toArray(certificateChainArray);
//		privateKey = privateKeyEntry.getPrivateKey();
//		this.encryptionAlgorithm = encryptionAlgorithm
        this(alias, privateKeyEntry.getPrivateKey(), (X509Certificate) privateKeyEntry.getCertificate(), privateKeyEntry.getCertificateChain(), encryptionAlgorithm);
    }

    public KSPrivateKeyEntry(final String alias, final PrivateKey privateKey, final X509Certificate x509Certificate, final Certificate[] certificates, EncryptionAlgorithm encryptionAlgorithm) {
        this.alias = alias;
        certificate = new CertificateToken(x509Certificate);
        this.encryptionAlgorithm = encryptionAlgorithm;
        final List<CertificateToken> x509CertificateList = new ArrayList<>();
        final Certificate[] simpleCertificateChain = certificates;
        for (final Certificate currentCertificate : simpleCertificateChain) {
            x509CertificateList.add(new CertificateToken((X509Certificate) currentCertificate));
        }
        final CertificateToken[] certificateChainArray = new CertificateToken[x509CertificateList.size()];
        certificateChain = x509CertificateList.toArray(certificateChainArray);
        this.privateKey = privateKey;
    }

    /**
     * Get the entry alias
     *
     * @return the alias
     */
    public String getAlias() {
        return alias;
    }

    @Override
    public CertificateToken getCertificate() {
        return certificate;
    }

    @Override
    public CertificateToken[] getCertificateChain() {
        return certificateChain;
    }

    /**
     * Get the private key
     *
     * @return the private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private EncryptionAlgorithm deriveEncryptionAlgorithm() throws DSSException {
        return EncryptionAlgorithm.forKey(certificate.getPublicKey());
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm() throws DSSException {
        return this.encryptionAlgorithm;
    }

}
