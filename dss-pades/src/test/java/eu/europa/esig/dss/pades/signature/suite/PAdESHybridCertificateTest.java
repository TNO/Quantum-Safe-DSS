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
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests signing a PDF document with a hybrid certificate with its associated private keys in a .p12 keystore.
 *
 * This requires an Internet connection to run due to  service.setTspSource(getGoodTsa()); - consider replacing with
 * a local and offline Tsa.
 */
public class PAdESHybridCertificateTest extends PKIFactoryAccess {

    // Default password for the local keystores used in this test.
    static final String password = "ks-password";
    // Allow keystore to be accessed in any method in the test (no need to pass it between functions).
    static KeyStore ks = null;


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
     * @param parameters PaDES signature parameters.
     * @return Alternative private key encoded in an KSPrivateKeyEntry object.
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     */
    private static KSPrivateKeyEntry prepareAltPrivateKey(X509Certificate x509Certificate, PAdESSignatureParameters parameters) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

        // We assume that the alternative private key is stored in the keystore with alias "hybrid-alt-good-user".
        PrivateKey altPrivateKey = (PrivateKey) ks.getKey("hybrid-alt-good-user", password.toCharArray());
        // Recall that the alternative private key has the same signing certificate as the private key.
        return new KSPrivateKeyEntry("hybrid-alt-good-user", altPrivateKey, x509Certificate, ks.getCertificateChain("hybrid-good-user"), parameters.getEncryptionAlgorithm());
    }

    /**
     * Gets certificate from a .p12 file that has alias "hybrid-good-user".
     *
     * @param name Name of .p12 file,
     * @return X509Certificate object with alias "hybrid-good-user" from the .p12 file.
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private static X509Certificate prepareCertificate(String name) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream("src/test/resources/" + name + ".p12");
        ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password.toCharArray());
        return (X509Certificate) ks.getCertificate("hybrid-good-user");
    }

    /**
     * Tests whether we can sign & verify two PAdES signatures from a hybrid signing certificate. Intended to be used
     * inside a wrapper function that passes the .p12 store as an argument.
     *
     * @param name Name of .p12 file,
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public void testHybridCertificate(String name) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        // Encodes a PDF file into a DSSDocument object
        DSSDocument toBeSigned = new InMemoryDocument(eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        // This PAdESService object creates and extends PAdES signatures
        PAdESService service = new PAdESService(getSelfSignedCertificateVerifier());
        // service.setTspSource(getGoodTsa());

        // Parameters for the PAdES signature, which includes things like (alt-)signature algorithm and (if visible) position in page
        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        // Get our signing certificate and encode it into yet another object, CertificateToken
        X509Certificate cert = prepareCertificate(name);
        CertificateToken certificateToken = new CertificateToken(cert);
        params.setSigningCertificate(certificateToken);

        // Prepare our primary and alt private key
        KSPrivateKeyEntry ksPrivateKey = preparePrivateKey();
        // This is a really stupid way of doing this, but alas its Java - essentially, ToBeSigned is just a byte[] variable.
        // All this does is hash the pdf document and the byte[] is the hash output.
        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        // Signs the hash of the document.
        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), ksPrivateKey);
        // Now this is stupid, this isn't just signDocument (which uses the params and signatureValue to generate a PAdES signature),
        // but will also verify whether the signature is correct and store it within the encoded bytes in the DSSDocument (use debugger to
        // see this in action and see file SignatureIntegrityValdiator.java in package eu.europa.esig.dss.spi.x509.
        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        // The content size needs to be increased if we are dealing with PQ schemes
        params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        params.setUseAltSignatureAndPublicKey(true);
        params.setSigningCertificate(certificateToken);
        params.setContentSize(12118);

        KSPrivateKeyEntry altKSPrivateKey = prepareAltPrivateKey(cert, params);

        // Same as above, except we are resigning our entire document (hence alt signature signs pdf content + classical PAdES signature
        dataToSign = service.getDataToSign(signedDocument, params);
        SignatureValue altSignatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), altKSPrivateKey);
        DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, altSignatureValue);

        // Object to validate the signed document
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        // Init report object which will hold reports of the validation process
        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        // Bug with 2 signatures which have the same ID
        List<String> signatureIdList = diagnosticData.getSignatureIdList();
        assertEquals(2, signatureIdList.size());

        // This does not actually perform any sort of validation, just returns a boolean that is set in the signDocument function.
        assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureIdList.get(0)));
        assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureIdList.get(1)));

        checkAllRevocationOnce(diagnosticData);

        // Make sure that our signatures signed different digests
        SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));

    }

    /**
     * Tests whether we can sign & verify two PAdES signatures from a hybrid signing certificate that contains two ECDSA keys.
     * Calls on testHybridCertificate to perform the actual test.
     *
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Test
    public void testDoubleHybridSignatureWithTwoECDSAKeys() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        testHybridCertificate("hybrid-good-user");
    }

    /**
     * Tests whether we can sign & verify two PAdES signatures from a hybrid signing certificate that contains an ECDSA and RSA key.
     * Calls on testHybridCertificate to perform the actual test.
     *
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Test
    public void testDoubleHybridSignatureWithECDSAAndRSAKeys() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        testHybridCertificate("hybrid-ecdsa-rsa-good-user");
    }

    /**
     * Tests whether we can sign & verify two PAdES signatures from a hybrid signing certificate that contains an ECDSA and Dilithium key.
     * Calls on testHybridCertificate to perform the actual test.
     *
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Test
    public void testDoubleHybridSignatureDilithium() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        testHybridCertificate("hybrid-pq-good-user");
    }

    @Test
    public void testDoubleHybridSignatureTest() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException {
        testHybridCertificate("test-falcon-works");
    }

    /**
     * Checks all revocations at once.
     *
     * @param diagnosticData Diagnostic data from document validation.
     */
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

    protected CertificateVerifier getSelfSignedCertificateVerifier() throws IOException {
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(null);

        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.importAsTrusted(new KeyStoreCertificateSource(new ByteArrayInputStream(IOUtils.toByteArray(Objects.requireNonNull(getClass().getResourceAsStream("/self-signed.jks")))), "JKS", password));

        cv.setTrustedCertSources(getTrustedCertificateSource());
        return cv;
    }
}

