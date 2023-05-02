//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;


/**
 * <p>Java class for CertificateRef complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateRef"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Origin" type="{http://dss.esig.europa.eu/validation/diagnostic}CertificateRefOriginType"/&gt;
 *         &lt;element name="IssuerSerial" type="{http://dss.esig.europa.eu/validation/diagnostic}IssuerSerial" minOccurs="0"/&gt;
 *         &lt;choice&gt;
 *           &lt;element name="DigestAlgoAndValue" type="{http://dss.esig.europa.eu/validation/diagnostic}DigestAlgoAndValue"/&gt;
 *           &lt;element name="SerialInfo" type="{http://dss.esig.europa.eu/validation/diagnostic}SignerInfo"/&gt;
 *         &lt;/choice&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateRef", propOrder = {
    "origin",
    "issuerSerial",
    "digestAlgoAndValue",
    "serialInfo"
})
public class XmlCertificateRef implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Origin", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter14 .class)
    protected CertificateRefOrigin origin;
    @XmlElement(name = "IssuerSerial")
    protected XmlIssuerSerial issuerSerial;
    @XmlElement(name = "DigestAlgoAndValue")
    protected XmlDigestAlgoAndValue digestAlgoAndValue;
    @XmlElement(name = "SerialInfo")
    protected XmlSignerInfo serialInfo;

    /**
     * Gets the value of the origin property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public CertificateRefOrigin getOrigin() {
        return origin;
    }

    /**
     * Sets the value of the origin property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOrigin(CertificateRefOrigin value) {
        this.origin = value;
    }

    /**
     * Gets the value of the issuerSerial property.
     * 
     * @return
     *     possible object is
     *     {@link XmlIssuerSerial }
     *     
     */
    public XmlIssuerSerial getIssuerSerial() {
        return issuerSerial;
    }

    /**
     * Sets the value of the issuerSerial property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlIssuerSerial }
     *     
     */
    public void setIssuerSerial(XmlIssuerSerial value) {
        this.issuerSerial = value;
    }

    /**
     * Gets the value of the digestAlgoAndValue property.
     * 
     * @return
     *     possible object is
     *     {@link XmlDigestAlgoAndValue }
     *     
     */
    public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
        return digestAlgoAndValue;
    }

    /**
     * Sets the value of the digestAlgoAndValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlDigestAlgoAndValue }
     *     
     */
    public void setDigestAlgoAndValue(XmlDigestAlgoAndValue value) {
        this.digestAlgoAndValue = value;
    }

    /**
     * Gets the value of the serialInfo property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSignerInfo }
     *     
     */
    public XmlSignerInfo getSerialInfo() {
        return serialInfo;
    }

    /**
     * Sets the value of the serialInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSignerInfo }
     *     
     */
    public void setSerialInfo(XmlSignerInfo value) {
        this.serialInfo = value;
    }

}
