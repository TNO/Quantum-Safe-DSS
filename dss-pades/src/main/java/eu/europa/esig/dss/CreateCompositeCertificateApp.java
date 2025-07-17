package eu.europa.esig.dss;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CreateCompositeCertificateApp {

    public static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now-24L * 60 * 60 * 1000);
        Date endDate = new Date(now + (365L * 24 * 60 * 60 * 1000));

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X500Name subjectName = new X500Name("CN=TEST");

        // Create the certificate builder
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subjectName,                // Issuer
                serialNumber,               // Serial Number
                startDate,                  // Validity Start
                endDate,                    // Validity End
                subjectName,                // Subject
                keyPair.getPublic()         // Public Key
        );

        // Create Content Signer (using SHA256withRSA)
        ContentSigner contentSigner = new JcaContentSignerBuilder(keyPair.getPrivate().getAlgorithm())
                .setProvider("BC")
                .build(keyPair.getPrivate());

        // Build the certificate
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        // Convert to Java's X509Certificate format
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateHolder);
    }

    public static KeyPair generateKeyPair(SignatureAlgorithm signatureAlgorithm) throws NoSuchAlgorithmException {
        KeyPairGeneratorSpi keyGen;
        switch (signatureAlgorithm) {
            case MLDSA44_RSA2048_PSS_SHA256:
                Security.addProvider(new BouncyCastleProvider());
                keyGen = new KeyPairGeneratorSpi.MLDSA44_RSA2048_PSS_SHA256();
                break;
            case MLDSA65_ECDSA_P256_SHA512:
                Security.addProvider(new BouncyCastleProvider());
                keyGen = new KeyPairGeneratorSpi.MLDSA65_ECDSA_P256_SHA512();
                break;
            case Falcon512_ECDSA_P256_SHA256:
                Security.addProvider(new BouncyCastleProvider());
                keyGen = new KeyPairGeneratorSpi.Falcon512_ECDSA_P256_SHA256();
                break;
            default:
                throw new NoSuchAlgorithmException();
        }
        return keyGen.generateKeyPair();
    }

    public static void saveToP12(
            String filename,
            KeyPair keyPair,
            X509Certificate hybridCertificate)
            throws Exception {
        PemObject pemObjectKey = new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filename + "-key.pem"))) {
            pemWriter.writeObject(pemObjectKey);
        }

        PemObject pemObjectCertificate = new PemObject("CERTIFICATE", hybridCertificate.getEncoded());
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filename + "-certificate.pem"))) {
            pemWriter.writeObject(pemObjectCertificate);
        }
    }

    public static void main(String[] args) throws Exception {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.MLDSA44_RSA2048_PSS_SHA256;
        KeyPair keyPair = generateKeyPair(signatureAlgorithm);
        X509Certificate certificate = generateCertificate(keyPair);
        saveToP12("dss-pades-openpdf/src/test/resources/composite",keyPair,certificate);
        System.out.println("Done");
    }
}
