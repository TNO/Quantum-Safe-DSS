//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:59 PM CEST 
//


package eu.europa.esig.dss.simplereport.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PDFAInfo complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFAInfo"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="PDFAProfile" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="ValidationMessages" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="Error" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="valid" type="{http://www.w3.org/2001/XMLSchema}boolean" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFAInfo", propOrder = {
    "pdfaProfile",
    "validationMessages"
})
public class XmlPDFAInfo
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "PDFAProfile")
    protected String pdfaProfile;
    @XmlElement(name = "ValidationMessages")
    protected XmlValidationMessages validationMessages;
    @XmlAttribute(name = "valid")
    protected Boolean valid;

    /**
     * Gets the value of the pdfaProfile property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPDFAProfile() {
        return pdfaProfile;
    }

    /**
     * Sets the value of the pdfaProfile property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPDFAProfile(String value) {
        this.pdfaProfile = value;
    }

    /**
     * Gets the value of the validationMessages property.
     * 
     * @return
     *     possible object is
     *     {@link XmlValidationMessages }
     *     
     */
    public XmlValidationMessages getValidationMessages() {
        return validationMessages;
    }

    /**
     * Sets the value of the validationMessages property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlValidationMessages }
     *     
     */
    public void setValidationMessages(XmlValidationMessages value) {
        this.validationMessages = value;
    }

    /**
     * Gets the value of the valid property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isValid() {
        return valid;
    }

    /**
     * Sets the value of the valid property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setValid(Boolean value) {
        this.valid = value;
    }

}
