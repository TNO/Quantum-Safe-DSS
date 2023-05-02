//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:16 PM CEST 
//


package eu.europa.esig.validationreport.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;


/**
 * <p>Java class for SignatureValidationProcessType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignatureValidationProcessType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="SignatureValidationProcessID" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="SignatureValidationServicePolicy" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="SignatureValidationPracticeStatement" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;any namespace='##other' minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignatureValidationProcessType", propOrder = {
    "signatureValidationProcessID",
    "signatureValidationServicePolicy",
    "signatureValidationPracticeStatement",
    "any"
})
public class SignatureValidationProcessType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "SignatureValidationProcessID", type = String.class)
    @XmlJavaTypeAdapter(Adapter5 .class)
    @XmlSchemaType(name = "anyURI")
    protected SignatureValidationProcessID signatureValidationProcessID;
    @XmlElement(name = "SignatureValidationServicePolicy")
    @XmlSchemaType(name = "anyURI")
    protected String signatureValidationServicePolicy;
    @XmlElement(name = "SignatureValidationPracticeStatement")
    @XmlSchemaType(name = "anyURI")
    protected String signatureValidationPracticeStatement;
    @XmlAnyElement(lax = true)
    protected Object any;

    /**
     * Gets the value of the signatureValidationProcessID property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public SignatureValidationProcessID getSignatureValidationProcessID() {
        return signatureValidationProcessID;
    }

    /**
     * Sets the value of the signatureValidationProcessID property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureValidationProcessID(SignatureValidationProcessID value) {
        this.signatureValidationProcessID = value;
    }

    /**
     * Gets the value of the signatureValidationServicePolicy property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignatureValidationServicePolicy() {
        return signatureValidationServicePolicy;
    }

    /**
     * Sets the value of the signatureValidationServicePolicy property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureValidationServicePolicy(String value) {
        this.signatureValidationServicePolicy = value;
    }

    /**
     * Gets the value of the signatureValidationPracticeStatement property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignatureValidationPracticeStatement() {
        return signatureValidationPracticeStatement;
    }

    /**
     * Sets the value of the signatureValidationPracticeStatement property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureValidationPracticeStatement(String value) {
        this.signatureValidationPracticeStatement = value;
    }

    /**
     * Gets the value of the any property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getAny() {
        return any;
    }

    /**
     * Sets the value of the any property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setAny(Object value) {
        this.any = value;
    }

}
