package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HybridCertTest {
    private static X509Certificate prepareCertificate() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        FileInputStream fis = new FileInputStream("src/test/resources/hybrid-good-user.p12");
        String password = "ks-password";
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password.toCharArray());
        return (X509Certificate) ks.getCertificate("hybrid-good-user");
    }

    private static SubjectPublicKeyInfo getSubjectAltPublicKey(X509Certificate x509Certificate) throws CertificateEncodingException, IOException {
        return SubjectPublicKeyInfo.getInstance(getAltExtensionValue(x509Certificate));
    }

    private static ASN1Encodable getAltExtensionValue(X509Certificate x509Certificate) throws CertificateEncodingException, IOException {
        X509CertificateHolder certHolder = new X509CertificateHolder(x509Certificate.getEncoded());
        return certHolder.getExtension(Extension.subjectAltPublicKeyInfo).getParsedValue();
    }

    @Test
    public void testAltSignatureValidityExternally() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException, CertException {
        X509Certificate cert = prepareCertificate();
        X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(cert.getEncoded());

        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(getSubjectAltPublicKey(cert));
        assertTrue(x509CertificateHolder.isAlternativeSignatureValid(contentVerifierProvider));
    }

    @Test
    public void testAltSignatureValidityInternally() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, CertException {
        X509Certificate cert = prepareCertificate();
        CertificateToken certificateToken = new CertificateToken(cert);
        assertTrue(certificateToken.isAltSignatureValid());
    }

}


