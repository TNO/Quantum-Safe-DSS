package eu.europa.esig.dss.enumerations;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.bike.BIKEKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.hqc.HQCKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.SNTRUPrimeKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class AlternateSignatureHelper {

    public static PublicKey convertToPublicKey(SubjectPublicKeyInfo altPub) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        ASN1ObjectIdentifier algOID = altPub.getAlgorithm().getAlgorithm();
        if (isDilithium(algOID)) {
            return new DilithiumKeyFactorySpi().generatePublic(altPub);
        } else if (isBike(algOID)) {
            return new BIKEKeyFactorySpi().generatePublic(altPub);
        } else if (isFalcon(algOID)) {
            return new FalconKeyFactorySpi().generatePublic(altPub);
        } else if (isSphincs(algOID)) {
            return new SPHINCSPlusKeyFactorySpi().generatePublic(altPub);
        } else if (isMcEliece(algOID)) {
            return new McElieceKeyFactorySpi().generatePublic(altPub);
        } else if (isFrodo(algOID)) {
            return new FrodoKeyFactorySpi().generatePublic(altPub);
        } else if (isMcEliece(algOID)) {
            return new McElieceKeyFactorySpi().generatePublic(altPub);
        } else if (isKyber(algOID)) {
            return new KyberKeyFactorySpi().generatePublic(altPub);
        } else if (isNTRUPrime(algOID)) {
            return new SNTRUPrimeKeyFactorySpi().generatePublic(altPub); // will this work?
        } else if (isHQC(algOID)) {
            return new HQCKeyFactorySpi().generatePublic(altPub);
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

    public static boolean isECDSA(ASN1ObjectIdentifier algOID) {
        return algOID.toString().equals("1.2.840.10045.2.1");
    }

    public static boolean isRSA(ASN1ObjectIdentifier algOID) {
        return algOID.toString().equals("1.2.840.113549.1.1.1");
    }


    private static boolean isDilithium(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.dilithium2) || algOID.equals(BCObjectIdentifiers.dilithium3) || algOID.equals(BCObjectIdentifiers.dilithium5) || algOID.equals(BCObjectIdentifiers.dilithium) || algOID.equals(BCObjectIdentifiers.dilithium2_aes) || algOID.equals(BCObjectIdentifiers.dilithium3_aes) || algOID.equals(BCObjectIdentifiers.dilithium5_aes);
    }

    private static boolean isFalcon(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.falcon) || algOID.equals(BCObjectIdentifiers.falcon_512) || algOID.equals(BCObjectIdentifiers.falcon_1024);
    }

    private static boolean isSphincs(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.sphincsPlus) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_128s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_128f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_192s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_192f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_256s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_shake_256f_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3) || algOID.equals(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
    }

    private static boolean isMcEliece(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_mceliece) || algOID.equals(BCObjectIdentifiers.mceliece348864f_r3) || algOID.equals(BCObjectIdentifiers.mceliece460896_r3) || algOID.equals(BCObjectIdentifiers.mceliece460896f_r3) || algOID.equals(BCObjectIdentifiers.mceliece6688128_r3) || algOID.equals(BCObjectIdentifiers.mceliece6688128f_r3) || algOID.equals(BCObjectIdentifiers.mceliece6960119_r3) || algOID.equals(BCObjectIdentifiers.mceliece6960119f_r3) || algOID.equals(BCObjectIdentifiers.mceliece8192128_r3) || algOID.equals(BCObjectIdentifiers.mceliece8192128f_r3);
    }


    private static boolean isFrodo(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_frodo) || algOID.equals(BCObjectIdentifiers.frodokem640aes) || algOID.equals(BCObjectIdentifiers.frodokem640shake) || algOID.equals(BCObjectIdentifiers.frodokem976aes) || algOID.equals(BCObjectIdentifiers.frodokem976shake) || algOID.equals(BCObjectIdentifiers.frodokem1344aes) || algOID.equals(BCObjectIdentifiers.frodokem1344shake);
    }


    private static boolean isKyber(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_kyber) || algOID.equals(BCObjectIdentifiers.kyber512) || algOID.equals(BCObjectIdentifiers.kyber768) || algOID.equals(BCObjectIdentifiers.kyber1024) || algOID.equals(BCObjectIdentifiers.kyber512_aes) || algOID.equals(BCObjectIdentifiers.kyber768_aes) || algOID.equals(BCObjectIdentifiers.kyber1024_aes);
    }


    private static boolean isNTRUPrime(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_ntruprime) || algOID.equals(BCObjectIdentifiers.pqc_kem_ntrulprime) || algOID.equals(BCObjectIdentifiers.ntrulpr653) || algOID.equals(BCObjectIdentifiers.ntrulpr761) || algOID.equals(BCObjectIdentifiers.ntrulpr857) || algOID.equals(BCObjectIdentifiers.ntrulpr953) || algOID.equals(BCObjectIdentifiers.ntrulpr1013) || algOID.equals(BCObjectIdentifiers.ntrulpr1277);
    }


    private static boolean isBike(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_bike) || algOID.equals(BCObjectIdentifiers.bike128) || algOID.equals(BCObjectIdentifiers.bike192) || algOID.equals(BCObjectIdentifiers.bike256);
    }


    private static boolean isHQC(ASN1ObjectIdentifier algOID) {
        return algOID.equals(BCObjectIdentifiers.pqc_kem_hqc) || algOID.equals(BCObjectIdentifiers.hqc128) || algOID.equals(BCObjectIdentifiers.hqc192) || algOID.equals(BCObjectIdentifiers.hqc256);
    }
}

