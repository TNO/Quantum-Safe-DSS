package eu.europa.esig.dss.cades.signature;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;

import java.util.HashMap;
import java.util.Map;

public class CustomCMSSignatureAlgorithmNameGenerator implements CMSSignatureAlgorithmNameGenerator {

    private final CMSSignatureAlgorithmNameGenerator defaultGenerator;
    private final Map<ASN1ObjectIdentifier,String> simpleAlgs = new HashMap<>();

    public CustomCMSSignatureAlgorithmNameGenerator() {
        //TODO: issue aanmaken in bouncy castle voor dit.
        this.defaultGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        simpleAlgs.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,"MLDSA44-RSA2048-PSS-SHA256");
        simpleAlgs.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,"MLDSA65-ECDSA-P256-SHA512");
        simpleAlgs.put(MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256,"Falcon512-ECDSA-P256-SHA256");
        simpleAlgs.put(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18"),"DILITHIUM3");
    }


    @Override
    public String getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg) {
        return simpleAlgs.getOrDefault(encryptionAlg.getAlgorithm(),defaultGenerator.getSignatureName(digestAlg,encryptionAlg));
    }
}
