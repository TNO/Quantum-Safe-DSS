package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
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

import static org.junit.jupiter.api.Assertions.*;

public class PAdESHybridCertificate extends PKIFactoryAccess { // MARKED AS POTENTIALLY INTERESTING SCRIPT

        @RepeatedTest(1)
        public void testDoubleHybridSignature() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

                DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

                PAdESService service = new PAdESService(getCompleteCertificateVerifier());
                service.setTspSource(getGoodTsa());

                PAdESSignatureParameters params = new PAdESSignatureParameters();

                params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

                FileInputStream fis = new FileInputStream("src/test/resources/hybrid-good-user.p12");
                String password = "ks-password";

                KeyStore ks = KeyStore.getInstance("pkcs12");
                ks.load(fis, password.toCharArray());

                PrivateKey privateKey = (PrivateKey) ks.getKey("hybrid-good-user", password.toCharArray());
                PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());

                KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain("hybrid-good-user"));
                KeyStore.PrivateKeyEntry altPrivateKeyEntry = new KeyStore.PrivateKeyEntry(altPrivateKey, ks.getCertificateChain("hybrid-alt-good-user"));

                X509Certificate cert = (X509Certificate) ks.getCertificate("hybrid-good-user");

                params.setSigningCertificate(new CertificateToken(cert));

                ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);

                KSPrivateKeyEntry KSPrivateKey = new KSPrivateKeyEntry("hybrid-good-user", privateKeyEntry);
                KSPrivateKeyEntry KSAltPrivateKey = new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKeyEntry);

                SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), KSPrivateKey);
                SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), KSAltPrivateKey);

                DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue, altSignatureValue);


                SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
                validator.setCertificateVerifier(getOfflineCertificateVerifier());
                Reports reports = validator.validateDocument();

                DiagnosticData diagnosticData = reports.getDiagnosticData();
                assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));

                // Bug with 2 signatures which have the same ID
                List<String> signatureIdList = diagnosticData.getSignatureIdList();
                assertEquals(2, signatureIdList.size());

                for (String signatureId : signatureIdList) {
                    assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
                }

                assertEquals(3, diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).size());

                checkAllRevocationOnce(diagnosticData);

                SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
                SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
                assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));
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

