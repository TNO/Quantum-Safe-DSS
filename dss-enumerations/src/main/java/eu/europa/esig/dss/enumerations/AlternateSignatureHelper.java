package eu.europa.esig.dss.enumerations;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyFactorySpi;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class AlternateSignatureHelper {

    /**
     * Converts a {@code SubjectPublicKeyInfo} into a {@code PublicKey} 
     * @param altPub {@code SubjectPublicKeyInfo} to be converted
     * @return {@code PublicKey}
     */
    public static PublicKey convertToPublicKey(SubjectPublicKeyInfo altPub) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        ASN1ObjectIdentifier algOID = altPub.getAlgorithm().getAlgorithm();
        if (isDilithium(algOID)) {
            return new DilithiumKeyFactorySpi().generatePublic(altPub);
        } else if (isFalcon(algOID)) {
            return new FalconKeyFactorySpi().generatePublic(altPub);
        } else if (isECDSA(algOID)) {
            return new KeyFactorySpi.EC().generatePublic(altPub);
        } else if (isRSA(algOID)) {
            RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(altPub);
            RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(rsaSpec);
        } else {
            throw new IOException("cannot find algorithm with oid " + altPub.getAlgorithm().getAlgorithm());
        }
    }

    /**
     * Whether OID points to an ECDSA instance.
     * @param algOID {@code ASN1ObjectIdentifier}
     * @return {@code boolean} if the OID points to an ECDSA instance 
     */
    public static boolean isECDSA(ASN1ObjectIdentifier algOID) {
        return algOID.toString().equals("1.2.840.10045.2.1");
    }

    /**
     * Whether OID points to an RSA instance.
     * @param algOID {@code ASN1ObjectIdentifier}
     * @return {@code boolean} if the OID points to an RSA instance 
     */
    public static boolean isRSA(ASN1ObjectIdentifier algOID) {
        return algOID.toString().equals("1.2.840.113549.1.1.1");
    }

    /**
     * Whether OID points to an Dilithium instance.
     * @param algOID {@code ASN1ObjectIdentifier}
     * @return {@code boolean} if the OID points to an Dilithium instance 
     */
    private static boolean isDilithium(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.dilithium2) || algOID.equals(BCObjectIdentifiers.dilithium3) || algOID.equals(BCObjectIdentifiers.dilithium5) || algOID.equals(BCObjectIdentifiers.dilithium) || algOID.equals(BCObjectIdentifiers.dilithium2_aes) || algOID.equals(BCObjectIdentifiers.dilithium3_aes) || algOID.equals(BCObjectIdentifiers.dilithium5_aes);
    }

    /**
     * Whether OID points to an Falcon instance.
     * @param algOID {@code ASN1ObjectIdentifier}
     * @return {@code boolean} if the OID points to an Falcon instance 
     */
    private static boolean isFalcon(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.falcon) || algOID.equals(BCObjectIdentifiers.falcon_512) || algOID.equals(BCObjectIdentifiers.falcon_1024);
    }
}
