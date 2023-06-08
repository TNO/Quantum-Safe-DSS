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
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests visibly signing a PDF document with a hybrid certificate with its associated private keys in a .p12 keystore.
 *
 * This requires an Internet connection to run due to  service.setTspSource(getGoodTsa()); - consider replacing with
 * a local and offline Tsa.
 */
public class PAdESHybridVisibleSignaturesTest extends AbstractPAdESTestValidation {

    // Default password for the local keystores used in this test.
    static final String password = "ks-password";
    // Allow keystore to be accessed in any method in the test (no need to pass it between functions).
    static KeyStore ks = null;
    // Visible signature stamp image
    private static DSSDocument image;
    // Parameters for PAdES signature.
    private static PAdESSignatureParameters signatureParameters;
    // Creates and extends PAdES signatures.
    private PAdESService service;
    // The document to sign.
    private DSSDocument documentToSign;


    /**
     * Gets certificate from the hybrid-pq-good-user.p12 file that has alias "hybrid-good-user".
     *
     * @return X509Certificate object with alias "hybrid-good-user" from the .p12 file.
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private static X509Certificate prepareCertificate() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream("src/test/resources/" + "hybrid-pq-good-user" + ".p12");
        ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password.toCharArray());
        return (X509Certificate) ks.getCertificate("hybrid-good-user");
    }

    /**
     * Returns the primary private key (i.e. the non-alternative) from the global keystore.
     *
     * @return Primary (i.e.e non-alternative) private key.
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     */
    private static KSPrivateKeyEntry preparePrivateKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey privateKey = (PrivateKey) ks.getKey("hybrid-good-user", password.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain("hybrid-good-user"));
        return new KSPrivateKeyEntry("hybrid-good-user", privateKeyEntry);
    }

    /**
     * Passes a PrivateKey object containing the alternative private key to a KSPrivateKeyEntry object.
     *
     * @param x509Certificate signing certificate.
     * @return Alternative private key encoded in an KSPrivateKeyEntry object.
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     */
    private static KSPrivateKeyEntry prepareAltPrivateKey(X509Certificate x509Certificate) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());
        return new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKey, x509Certificate, ks.getCertificateChain("hybrid-good-user"), signatureParameters.getAltEncryptionAlgorithm());
    }

    /**
     * Before each test, initialise and configure the various global variables.
     * @throws Exception
     */
    @BeforeEach
    public void init() throws Exception {
        // Encodes a PDF file into a DSSDocument object
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        // Parameters for the PAdES signature, which includes things like (alt-)signature algorithm and (if visible) position in page
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());

        // Get our signing certificate and encode it into yet another object, CertificateToken
        X509Certificate cert = prepareCertificate();
        CertificateToken certificateToken = new CertificateToken(cert);
        signatureParameters.setSigningCertificate(certificateToken);
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        // This PAdESService object creates and extends PAdES signatures
        service = new PAdESService(getSelfSignedCertificateVerifier());
        // Visible signature stamp image
        image = new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG);
    }

    protected CertificateVerifier getSelfSignedCertificateVerifier() throws IOException {
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(null);

        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.importAsTrusted(new KeyStoreCertificateSource(new ByteArrayInputStream(IOUtils.toByteArray(Objects.requireNonNull(getClass().getResourceAsStream("/self-signed.jks")))), "JKS", password));

        cv.setTrustedCertSources(getTrustedCertificateSource());
        return cv;
    }

    /**
     * Tests whether we are able to visibly sign a pdf document with a hybrid certificate.
     *
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void hybridVisibleSignature() throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        // Prepare our primary and alt private key
        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(signatureParameters.getSigningCertificate().getCertificate());

        // Parameters for the signature stamp image.
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        signatureParameters.setImageParameters(imageParameters);
        imageParameters.setImage(image);

        // Set width, height and position of stamp.
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

        // signs document
        documentToSign = signDSSDocument(ksPrivateKey);

        // change the field parameters for the alt signature stamp.
        fieldParameters.setOriginX(300);
        fieldParameters.setOriginY(100);

        // See method description for this sneaky way of doing things
        signatureParameters.prepareParametersForHybrid();

        // signs document using alternative private key
        documentToSign = signDSSDocument(altKSPrivateKey);

        // documentSign cannot be null
        assertNotNull(documentToSign);

        documentToSign.save("/home/joao/visible.pdf");
    }

    /**
     * Signs a DSSDocument diven a private key and asserts whether it is valid.
     *
     * @param privateKeyEntry Private signing key.
     * @return Signed document.
     * @throws IOException
     */
    private DSSDocument signDSSDocument(KSPrivateKeyEntry privateKeyEntry) throws IOException {
        // This is a really stupid way of doing this, but alas its Java - essentially, ToBeSigned is just a byte[] variable.
        // All this does is hash the pdf document and the byte[] is the hash output.
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        // Signs the hash of the document.
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKeyEntry);
        // Noww this is stupid, this isn't just signDocument (which uses the params and signatureValue to generate a PAdES signature),
        // but will also verify whether the signature is correct and store it within the encoded bytes in the DSSDocument (use debugger to
        // see this in action and see file SignatureIntegrityValdiator.java in package eu.europa.esig.dss.spi.x509.
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        // Object to validate the signed document
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        // Init report object which will hold reports of the validation process
        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<String> signatureIdList = diagnosticData.getSignatureIdList();

        // This does not actually perform any sort of validation, just returns a boolean that is set in the signDocument function.
        assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureIdList.get(0)));
        if(signatureIdList.size() == 2){
            assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureIdList.get(1)));
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

    /**
     * Returns signing alias.
     *
     * TODO: is this actually doing anything useful? This is what I get for not commenting code early enough. I think it is used in the getToken() method.
     *
     * @return signing alias with is equal to "good-user"
     */
    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
