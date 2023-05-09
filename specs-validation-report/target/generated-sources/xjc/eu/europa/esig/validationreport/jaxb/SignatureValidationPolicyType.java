//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:34 PM CEST 
//


package eu.europa.esig.validationreport.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import eu.europa.esig.xades.jaxb.xades132.SignaturePolicyIdentifierType;


/**
 * <p>Java class for SignatureValidationPolicyType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignatureValidationPolicyType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="SignaturePolicyIdentifier" type="{http://uri.etsi.org/01903/v1.3.2#}SignaturePolicyIdentifierType"/&gt;
 *         &lt;element name="PolicyName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="FormalPolicyURI" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="ReadablePolicyURI" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="FormalPolicyObject" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignatureValidationPolicyType", propOrder = {
    "signaturePolicyIdentifier",
    "policyName",
    "formalPolicyURI",
    "readablePolicyURI",
    "formalPolicyObject"
})
public class SignatureValidationPolicyType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "SignaturePolicyIdentifier", required = true)
    protected SignaturePolicyIdentifierType signaturePolicyIdentifier;
    @XmlElement(name = "PolicyName")
    protected String policyName;
    @XmlElement(name = "FormalPolicyURI")
    @XmlSchemaType(name = "anyURI")
    protected String formalPolicyURI;
    @XmlElement(name = "ReadablePolicyURI")
    @XmlSchemaType(name = "anyURI")
    protected String readablePolicyURI;
    @XmlElement(name = "FormalPolicyObject")
    protected VOReferenceType formalPolicyObject;

    /**
     * Gets the value of the signaturePolicyIdentifier property.
     * 
     * @return
     *     possible object is
     *     {@link SignaturePolicyIdentifierType }
     *     
     */
    public SignaturePolicyIdentifierType getSignaturePolicyIdentifier() {
        return signaturePolicyIdentifier;
    }

    /**
     * Sets the value of the signaturePolicyIdentifier property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignaturePolicyIdentifierType }
     *     
     */
    public void setSignaturePolicyIdentifier(SignaturePolicyIdentifierType value) {
        this.signaturePolicyIdentifier = value;
    }

    /**
     * Gets the value of the policyName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPolicyName() {
        return policyName;
    }

    /**
     * Sets the value of the policyName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPolicyName(String value) {
        this.policyName = value;
    }

    /**
     * Gets the value of the formalPolicyURI property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getFormalPolicyURI() {
        return formalPolicyURI;
    }

    /**
     * Sets the value of the formalPolicyURI property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setFormalPolicyURI(String value) {
        this.formalPolicyURI = value;
    }

    /**
     * Gets the value of the readablePolicyURI property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReadablePolicyURI() {
        return readablePolicyURI;
    }

    /**
     * Sets the value of the readablePolicyURI property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReadablePolicyURI(String value) {
        this.readablePolicyURI = value;
    }

    /**
     * Gets the value of the formalPolicyObject property.
     * 
     * @return
     *     possible object is
     *     {@link VOReferenceType }
     *     
     */
    public VOReferenceType getFormalPolicyObject() {
        return formalPolicyObject;
    }

    /**
     * Sets the value of the formalPolicyObject property.
     * 
     * @param value
     *     allowed object is
     *     {@link VOReferenceType }
     *     
     */
    public void setFormalPolicyObject(VOReferenceType value) {
        this.formalPolicyObject = value;
    }

}