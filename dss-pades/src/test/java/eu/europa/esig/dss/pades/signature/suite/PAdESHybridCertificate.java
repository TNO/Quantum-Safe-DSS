package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PAdESHybridCertificate extends PKIFactoryAccess { // MARKED AS POTENTIALLY INTERESTING SCRIPT

        @RepeatedTest(1)
        public void testDoubleHybridSignature() {

            DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

            PAdESService service = new PAdESService(getCompleteCertificateVerifier());
            service.setTspSource(getGoodTsa());

            PAdESSignatureParameters params = new PAdESSignatureParameters();
            params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
            params.setSigningCertificate(getSigningCert());

            ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);

            SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
            SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getAltPrivateKeyEntry());

            DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue, altSignatureValue);


            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
            validator.setCertificateVerifier(getOfflineCertificateVerifier());
            Reports reports1 = validator.validateDocument();

            DiagnosticData diagnosticData = reports1.getDiagnosticData();
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

