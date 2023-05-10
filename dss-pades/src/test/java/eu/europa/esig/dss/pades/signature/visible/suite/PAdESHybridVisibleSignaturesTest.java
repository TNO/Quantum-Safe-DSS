package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESHybridVisibleSignaturesTest extends AbstractPAdESTestValidation {

    static final String password = "ks-password";
    static KeyStore ks = null;
    private static DSSDocument image;
    private static PAdESSignatureParameters signatureParameters;
    private PAdESService service;
    private DSSDocument documentToSign;

    private static X509Certificate prepareCertificate() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream("src/test/resources/" + "hybrid-pq-good-user" + ".p12");
        ks = KeyStore.getInstance("pkcs12"); // 1.3.6.1.4.1.2.267.7.6.5
        ks.load(fis, password.toCharArray());
        return (X509Certificate) ks.getCertificate("hybrid-good-user");
    }

    private static KSPrivateKeyEntry preparePrivateKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey privateKey = (PrivateKey) ks.getKey("hybrid-good-user", password.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain("hybrid-good-user"));
        return new KSPrivateKeyEntry("hybrid-good-user", privateKeyEntry);
    }

    private static KSPrivateKeyEntry prepareAltPrivateKey(X509Certificate x509Certificate) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());
        return new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKey, x509Certificate, ks.getCertificateChain("hybrid-good-user"), signatureParameters.getAltEncryptionAlgorithm());
    }

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());

        X509Certificate cert = prepareCertificate();
        CertificateToken certificateToken = new CertificateToken(cert);

        signatureParameters.setSigningCertificate(certificateToken);


        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        image = new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG);
    }

    @Test
    public void hybridVisibleSignature() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {

        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(signatureParameters.getSigningCertificate().getCertificate());


        SignatureImageParameters imageParameters = new SignatureImageParameters();
        signatureParameters.setImageParameters(imageParameters);
        imageParameters.setImage(image);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

        documentToSign = signDSSDocument(ksPrivateKey);

        fieldParameters.setOriginX(300);
        fieldParameters.setOriginY(100);

        signatureParameters.prepareParametersForHybrid();

        documentToSign = signDSSDocument(altKSPrivateKey);

        assertNotNull(documentToSign);
    }

    private DSSDocument signDSSDocument(KSPrivateKeyEntry privateKeyEntry) throws IOException {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKeyEntry);
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports2 = validator.validateDocument();
        DiagnosticData diagnosticData2 = reports2.getDiagnosticData();
        List<String> signatureIdList = diagnosticData2.getSignatureIdList();

        assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(0)));
        if(signatureIdList.size() == 2){
            assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureIdList.get(1)));
        }
        return signedDocument;
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        // skip (different tests)
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
