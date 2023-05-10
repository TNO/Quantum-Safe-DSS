package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.RepeatedTest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class PAdESHybridCertificateTest extends PKIFactoryAccess {
    static final String password = "ks-password";
    static KeyStore ks = null;



    private static KSPrivateKeyEntry preparePrivateKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey privateKey = (PrivateKey) ks.getKey("hybrid-good-user", password.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain("hybrid-good-user"));
        return new KSPrivateKeyEntry("hybrid-good-user", privateKeyEntry);
    }

    private static KSPrivateKeyEntry prepareAltPrivateKey(X509Certificate x509Certificate, PAdESSignatureParameters parameters) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());
        return new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKey, x509Certificate, ks.getCertificateChain("hybrid-good-user"), parameters.getAltEncryptionAlgorithm());
    }

    private static X509Certificate prepareCertificate(String name) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream("src/test/resources/" + name + ".p12");
        ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password.toCharArray());
        return (X509Certificate) ks.getCertificate("hybrid-good-user");
    }

    @RepeatedTest(1)
    public void testDoubleHybridSignatureWithTwoECDSAKeys() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);


        X509Certificate cert = prepareCertificate("hybrid-good-user");
        CertificateToken certificateToken = new CertificateToken(cert);

        params.setSigningCertificate(certificateToken);

        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(cert, params);

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), ksPrivateKey);
        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        params.prepareParametersForHybrid();

        dataToSign = service.getDataToSign(signedDocument, params);
        SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), altKSPrivateKey);
        DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, altSignatureValue);

        validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports2 = validator.validateDocument();
        DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

        // Bug with 2 signatures which have the same ID
        List<String> signatureIdList = diagnosticData2.getSignatureIdList();
        assertEquals(2, signatureIdList.size());

        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(0)));
        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(1)));


        assertEquals(1, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

        checkAllRevocationOnce(diagnosticData2);

        SignatureWrapper signatureOne = diagnosticData2.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData2.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));
    }

    @RepeatedTest(1)
    public void testDoubleHybridSignatureWithECDSAAndRSAKeys() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);


        X509Certificate cert = prepareCertificate("hybrid-ecdsa-rsa-good-user");
        CertificateToken certificateToken = new CertificateToken(cert);

        params.setSigningCertificate(certificateToken);

        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(cert, params);

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), ksPrivateKey);
        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        params.prepareParametersForHybrid();

        dataToSign = service.getDataToSign(signedDocument, params);
        SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), altKSPrivateKey);
        DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, altSignatureValue);

        validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports2 = validator.validateDocument();
        DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

        // Bug with 2 signatures which have the same ID
        List<String> signatureIdList = diagnosticData2.getSignatureIdList();
        assertEquals(2, signatureIdList.size());

        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(0)));
        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(1)));


        assertEquals(1, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

        checkAllRevocationOnce(diagnosticData2);

        SignatureWrapper signatureOne = diagnosticData2.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData2.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));
    }

    @RepeatedTest(1)
    public void testDoubleHybridSignatureDilithium() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        X509Certificate cert = prepareCertificate("hybrid-pq-good-user");
        CertificateToken certificateToken = new CertificateToken(cert);

        params.setSigningCertificate(certificateToken);

        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(cert, params);

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), ksPrivateKey);
        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        params.prepareParametersForHybrid();

        dataToSign = service.getDataToSign(signedDocument, params);
        SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), altKSPrivateKey);
        DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, altSignatureValue);

        validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports2 = validator.validateDocument();
        DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

        // Bug with 2 signatures which have the same ID
        List<String> signatureIdList = diagnosticData2.getSignatureIdList();
        assertEquals(2, signatureIdList.size());

        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(0)));
        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(1)));


        assertEquals(1, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

        checkAllRevocationOnce(diagnosticData2);

        SignatureWrapper signatureOne = diagnosticData2.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData2.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));

    }


    private void checkAllRevocationOnce(DiagnosticData diagnosticData) {
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper certificateWrapper : usedCertificates) {
            if (certificateWrapper.isTrusted() || certificateWrapper.isSelfSigned() || certificateWrapper.isIdPkixOcspNoCheck()) {
                continue;
            }
            int nbRevoc = certificateWrapper.getCertificateRevocationData().size();
            assertEquals(0, nbRevoc, "Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc);
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

