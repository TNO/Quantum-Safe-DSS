//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:40 PM CEST 
//


package eu.europa.esig.saml.jaxb.protocol;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RequestedAuthnContextType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RequestedAuthnContextType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;choice&gt;
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef" maxOccurs="unbounded"/&gt;
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDeclRef" maxOccurs="unbounded"/&gt;
 *       &lt;/choice&gt;
 *       &lt;attribute name="Comparison" type="{urn:oasis:names:tc:SAML:2.0:protocol}AuthnContextComparisonType" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RequestedAuthnContextType", propOrder = {
    "authnContextClassRef",
    "authnContextDeclRef"
})
public class RequestedAuthnContextType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "AuthnContextClassRef", namespace = "urn:oasis:names:tc:SAML:2.0:assertion")
    @XmlSchemaType(name = "anyURI")
    protected List<String> authnContextClassRef;
    @XmlElement(name = "AuthnContextDeclRef", namespace = "urn:oasis:names:tc:SAML:2.0:assertion")
    @XmlSchemaType(name = "anyURI")
    protected List<String> authnContextDeclRef;
    @XmlAttribute(name = "Comparison")
    protected AuthnContextComparisonType comparison;

    /**
     * Gets the value of the authnContextClassRef property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the authnContextClassRef property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAuthnContextClassRef().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getAuthnContextClassRef() {
        if (authnContextClassRef == null) {
            authnContextClassRef = new ArrayList<String>();
        }
        return this.authnContextClassRef;
    }

    /**
     * Gets the value of the authnContextDeclRef property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the authnContextDeclRef property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAuthnContextDeclRef().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getAuthnContextDeclRef() {
        if (authnContextDeclRef == null) {
            authnContextDeclRef = new ArrayList<String>();
        }
        return this.authnContextDeclRef;
    }

    /**
     * Gets the value of the comparison property.
     * 
     * @return
     *     possible object is
     *     {@link AuthnContextComparisonType }
     *     
     */
    public AuthnContextComparisonType getComparison() {
        return comparison;
    }

    /**
     * Sets the value of the comparison property.
     * 
     * @param value
     *     allowed object is
     *     {@link AuthnContextComparisonType }
     *     
     */
    public void setComparison(AuthnContextComparisonType value) {
        this.comparison = value;
    }

}
