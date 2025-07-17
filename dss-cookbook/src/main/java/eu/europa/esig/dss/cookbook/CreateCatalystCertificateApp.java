package eu.europa.esig.dss.cookbook;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPublicKey;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Date;


public class CreateCatalystCertificateApp {

    /**
     * Creates a hybrid certificate using specified encryption and signature algorithms.
     */
    public static X509Certificate createHybridCertificate(
            KeyPair primaryKeyPair,
            KeyPair secondaryKeyPair,
            SignatureAlgorithm primarySignatureAlgorithm,
            SignatureAlgorithm secondarySignatureAlgorithm
    ) throws Exception {

        X500Name issuer = new X500Name("CN=TEST");
        X500Name subject = new X500Name("CN=TEST");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, primaryKeyPair.getPublic()
        );

        // Add standard extensions
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        // Add SubjectAltPublicKeyInfo extension
        ASN1EncodableVector altPubKeyVector = new ASN1EncodableVector();

        AlgorithmIdentifier algorithmIdentifier;
        if (secondaryKeyPair.getPublic() instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) secondaryKeyPair.getPublic();
            ECPoint ecPoint = ecPublicKey.getW();
            byte[] xCoord = ecPoint.getAffineX().toByteArray();
            byte[] yCoord = ecPoint.getAffineY().toByteArray();

            xCoord = Arrays.copyOfRange(xCoord, Math.max(0, xCoord.length - 32), xCoord.length);
            yCoord = Arrays.copyOfRange(yCoord, Math.max(0, yCoord.length - 32), yCoord.length);

            byte[] uncompressedPublicKey = new byte[65];
            uncompressedPublicKey[0] = 0x04; // Uncompressed point indicator
            System.arraycopy(xCoord, 0, uncompressedPublicKey, 1, 32);
            System.arraycopy(yCoord, 0, uncompressedPublicKey, 33, 32);

            algorithmIdentifier = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.10045.2.1"), // EC OID
                    new ASN1ObjectIdentifier("1.2.840.10045.3.1.7") // secp256r1 curve OID
            );

            altPubKeyVector.add(algorithmIdentifier);
            altPubKeyVector.add(new DERBitString(uncompressedPublicKey));
        } else if (secondaryKeyPair.getPublic() instanceof RSAPublicKey) {
            algorithmIdentifier = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), // RSA Encryption OID
                    DERNull.INSTANCE // NULL parameters
            );

            RSAPublicKey rsaPublicKey = (RSAPublicKey) secondaryKeyPair.getPublic();
            ASN1EncodableVector publicKeyVector = new ASN1EncodableVector();
            publicKeyVector.add(new ASN1Integer(rsaPublicKey.getModulus())); // Modulus
            publicKeyVector.add(new ASN1Integer(rsaPublicKey.getPublicExponent())); // Exponent

            DERBitString publicKeyBitString = new DERBitString(new DERSequence(publicKeyVector));

            altPubKeyVector.add(algorithmIdentifier); // Algorithm Identifier
            altPubKeyVector.add(publicKeyBitString);  // Public Key
        } else if (secondaryKeyPair.getPublic() instanceof BCFalconPublicKey) {
            //We do nothing since we fix this later due to a weird issue with sequences.
            altPubKeyVector.add(new DEROctetString(secondaryKeyPair.getPublic().getEncoded()));
        } else if (secondaryKeyPair.getPublic() instanceof DilithiumPublicKey) {
            //We do nothing since we fix this later due to a weird issue with sequences.
            //TODO: implement this
        }

        certBuilder.addExtension(
                Extension.subjectAltPublicKeyInfo,
                true,
                new DERSequence(altPubKeyVector)
        );

        // Add alternative signature algorithm OID
        ASN1EncodableVector extValueVector = new ASN1EncodableVector();
        extValueVector.add(new ASN1ObjectIdentifier(secondarySignatureAlgorithm.getOid()));
        certBuilder.addExtension(
                Extension.altSignatureAlgorithm,
                true,
                new DERSequence(extValueVector)
        );

        // Add alternative signature value
        byte[] certificateData = certBuilder.build(
                new JcaContentSignerBuilder(primarySignatureAlgorithm.getJCEId()).build(primaryKeyPair.getPrivate())
        ).getEncoded();

        Signature altSignature = Signature.getInstance(secondarySignatureAlgorithm.getJCEId());
        altSignature.initSign(secondaryKeyPair.getPrivate());
        altSignature.update(certificateData);
        byte[] altSignatureBytes = altSignature.sign();

        certBuilder.addExtension(
                Extension.altSignatureValue,
                true,
                new DERBitString(altSignatureBytes)
        );

        // Build final certificate
        ContentSigner signer = new JcaContentSignerBuilder(primarySignatureAlgorithm.getJCEId()).build(primaryKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    /**
     * Saves the generated hybrid certificate to a PKCS#12 file.
     */
    public static void saveToP12(
            String filename,
            KeyPair primaryKeyPair,
            KeyPair secondaryKeyPair,
            X509Certificate hybridCertificate,
            String password
    ) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        // Add the hybrid certificate with primary key
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
                primaryKeyPair.getPrivate(),
                new Certificate[]{hybridCertificate}
        );
        keyStore.setEntry("hybrid-good-user", privateKeyEntry, new KeyStore.PasswordProtection(password.toCharArray()));

        // Add the secondary private key
        keyStore.setKeyEntry(
                "hybrid-alt-good-user",
                secondaryKeyPair.getPrivate(),
                password.toCharArray(),
                new Certificate[]{hybridCertificate}
        );

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Utility methods to generate KeyPairs dynamically based on EncryptionAlgorithm.
     */
    public static KeyPair generateKeyPair(EncryptionAlgorithm algorithm) throws Exception {
        KeyPairGenerator keyGen;
        switch (algorithm) {
            case RSA:
                keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                break;
            case ECDSA:
            case PLAIN_ECDSA:
                keyGen = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
                keyGen.initialize(ecSpec);  // Initialize the key generator with the curve spec
                break;
            case FALCON_512:
                Security.addProvider(new BouncyCastlePQCProvider());
                keyGen = KeyPairGenerator.getInstance("Falcon", "BCPQC");
                keyGen.initialize(FalconParameterSpec.falcon_512);
                break;
            case DILITHIUM3:
                Security.addProvider(new BouncyCastlePQCProvider());
                keyGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
                keyGen.initialize(DilithiumParameterSpec.dilithium3);
                break;
            default:
                throw new IllegalArgumentException("Unsupported encryption algorithm: " + algorithm.getName());
        }
        return keyGen.generateKeyPair();
    }

    /**
     * Main method to demonstrate the hybrid certificate generation.
     */
    public static void main(String[] args) throws Exception {
        SignatureAlgorithm primarySignatureAlgorithm = SignatureAlgorithm.FALCON_512;
        SignatureAlgorithm secondarySignatureAlgorithm = SignatureAlgorithm.FALCON_512;
        long start = System.currentTimeMillis();
        KeyPair primaryKeyPair = generateKeyPair(primarySignatureAlgorithm.getEncryptionAlgorithm());
        KeyPair secondaryKeyPair = generateKeyPair(secondarySignatureAlgorithm.getEncryptionAlgorithm());

        X509Certificate hybridCertificate = createHybridCertificate(
                primaryKeyPair, secondaryKeyPair, primarySignatureAlgorithm, secondarySignatureAlgorithm
        );
        System.out.println(System.currentTimeMillis()-start);
        saveToP12("dss-pades-openpdf/src/test/resources/test-falcon-works-bc179.p12", primaryKeyPair, secondaryKeyPair, hybridCertificate, "ks-password");
        System.out.println("Hybrid certificate created and saved.");
    }
}
