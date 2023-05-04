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
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class PAdESHybridCertificate extends PKIFactoryAccess { // MARKED AS POTENTIALLY INTERESTING SCRIPT

    @RepeatedTest(1)
    public void testDoubleHybridSignature() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        FileInputStream fis = new FileInputStream("src/test/resources/hybrid-good-user.p12");
        String password = "ks-password";
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password.toCharArray());

        X509Certificate cert = (X509Certificate) ks.getCertificate("hybrid-good-user");
        params.setSigningCertificate(new CertificateToken(cert));

        byte[] octetString = new CertificateToken(cert).getAltSignature();

        PrivateKey privateKey = (PrivateKey) ks.getKey("hybrid-good-user", password.toCharArray());
        PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain("hybrid-good-user"));
        KeyStore.PrivateKeyEntry altPrivateKeyEntry = new KeyStore.PrivateKeyEntry(altPrivateKey, ks.getCertificateChain("hybrid-alt-good-user"));
        KSPrivateKeyEntry KSPrivateKey = new KSPrivateKeyEntry("hybrid-good-user", privateKeyEntry);
        KSPrivateKeyEntry KSAltPrivateKey = new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKeyEntry);

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), KSPrivateKey);
        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports1 = validator.validateDocument();

        DiagnosticData diagnosticData1 = reports1.getDiagnosticData();
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData1.getSignatureFormat(diagnosticData1.getFirstSignatureId()));

        params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        params.setSigningCertificate(new CertificateToken(cert));
        service.setTspSource(getAlternateGoodTsa());

        dataToSign = service.getDataToSign(signedDocument, params);
        SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), KSAltPrivateKey);
        DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, altSignatureValue);

        validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports2 = validator.validateDocument();
        DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

        // Bug with 2 signatures which have the same ID
        List<String> signatureIdList = diagnosticData2.getSignatureIdList();
        assertEquals(2, signatureIdList.size());
        for (String signatureId : signatureIdList) {
            assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureId));
        }

        assertEquals(3, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

        checkAllRevocationOnce(diagnosticData2);

        checkAllPreviousRevocationDataInNewDiagnosticData(diagnosticData1, diagnosticData2);

        SignatureWrapper signatureOne = diagnosticData2.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData2.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));

    }

    private void checkAllPreviousRevocationDataInNewDiagnosticData(DiagnosticData diagnosticData1, DiagnosticData diagnosticData2) {

        Set<RevocationWrapper> allRevocationData1 = diagnosticData1.getAllRevocationData();
        Set<RevocationWrapper> allRevocationData2 = diagnosticData2.getAllRevocationData();

        for (RevocationWrapper revocationWrapper : allRevocationData1) {
            boolean found = false;
            for (RevocationWrapper revocationWrapper2 : allRevocationData2) {
                if (Utils.areStringsEqual(revocationWrapper.getId(), revocationWrapper2.getId())) {
                    found = true;
                }
            }
            assertTrue(found);
        }
    }

    private void checkAllRevocationOnce(DiagnosticData diagnosticData) {
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper certificateWrapper : usedCertificates) {
            if (certificateWrapper.isTrusted() || certificateWrapper.isSelfSigned() || certificateWrapper.isIdPkixOcspNoCheck()) {
                continue;
            }
            int nbRevoc = certificateWrapper.getCertificateRevocationData().size();
            assertEquals(1, nbRevoc, "Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc);
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

