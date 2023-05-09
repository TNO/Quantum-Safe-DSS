//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:59 PM CEST 
//


package eu.europa.esig.dss.simplereport.jaxb;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the eu.europa.esig.dss.simplereport.jaxb package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _SimpleReport_QNAME = new QName("http://dss.esig.europa.eu/validation/simple-report", "SimpleReport");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.europa.esig.dss.simplereport.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link XmlSimpleReport }
     * 
     */
    public XmlSimpleReport createXmlSimpleReport() {
        return new XmlSimpleReport();
    }

    /**
     * Create an instance of {@link XmlValidationPolicy }
     * 
     */
    public XmlValidationPolicy createXmlValidationPolicy() {
        return new XmlValidationPolicy();
    }

    /**
     * Create an instance of {@link XmlPDFAInfo }
     * 
     */
    public XmlPDFAInfo createXmlPDFAInfo() {
        return new XmlPDFAInfo();
    }

    /**
     * Create an instance of {@link XmlDetails }
     * 
     */
    public XmlDetails createXmlDetails() {
        return new XmlDetails();
    }

    /**
     * Create an instance of {@link XmlMessage }
     * 
     */
    public XmlMessage createXmlMessage() {
        return new XmlMessage();
    }

    /**
     * Create an instance of {@link XmlSignature }
     * 
     */
    public XmlSignature createXmlSignature() {
        return new XmlSignature();
    }

    /**
     * Create an instance of {@link XmlSignatureScope }
     * 
     */
    public XmlSignatureScope createXmlSignatureScope() {
        return new XmlSignatureScope();
    }

    /**
     * Create an instance of {@link XmlTimestamps }
     * 
     */
    public XmlTimestamps createXmlTimestamps() {
        return new XmlTimestamps();
    }

    /**
     * Create an instance of {@link XmlTimestamp }
     * 
     */
    public XmlTimestamp createXmlTimestamp() {
        return new XmlTimestamp();
    }

    /**
     * Create an instance of {@link XmlCertificateChain }
     * 
     */
    public XmlCertificateChain createXmlCertificateChain() {
        return new XmlCertificateChain();
    }

    /**
     * Create an instance of {@link XmlCertificate }
     * 
     */
    public XmlCertificate createXmlCertificate() {
        return new XmlCertificate();
    }

    /**
     * Create an instance of {@link XmlTrustAnchors }
     * 
     */
    public XmlTrustAnchors createXmlTrustAnchors() {
        return new XmlTrustAnchors();
    }

    /**
     * Create an instance of {@link XmlTrustAnchor }
     * 
     */
    public XmlTrustAnchor createXmlTrustAnchor() {
        return new XmlTrustAnchor();
    }

    /**
     * Create an instance of {@link XmlSignatureLevel }
     * 
     */
    public XmlSignatureLevel createXmlSignatureLevel() {
        return new XmlSignatureLevel();
    }

    /**
     * Create an instance of {@link XmlTimestampLevel }
     * 
     */
    public XmlTimestampLevel createXmlTimestampLevel() {
        return new XmlTimestampLevel();
    }

    /**
     * Create an instance of {@link XmlSemantic }
     * 
     */
    public XmlSemantic createXmlSemantic() {
        return new XmlSemantic();
    }

    /**
     * Create an instance of {@link XmlValidationMessages }
     * 
     */
    public XmlValidationMessages createXmlValidationMessages() {
        return new XmlValidationMessages();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSimpleReport }{@code >}
     * 
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link XmlSimpleReport }{@code >}
     */
    @XmlElementDecl(namespace = "http://dss.esig.europa.eu/validation/simple-report", name = "SimpleReport")
    public JAXBElement<XmlSimpleReport> createSimpleReport(XmlSimpleReport value) {
        return new JAXBElement<XmlSimpleReport>(_SimpleReport_QNAME, XmlSimpleReport.class, null, value);
    }

}
