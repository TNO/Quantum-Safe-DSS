//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:27 PM CET 
//


package eu.europa.esig.saml.jaxb.authn.context;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for GoverningAgreementRefType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="GoverningAgreementRefType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;attribute name="governingAgreementRef" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "GoverningAgreementRefType")
public class GoverningAgreementRefType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlAttribute(name = "governingAgreementRef", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String governingAgreementRef;

    /**
     * Gets the value of the governingAgreementRef property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getGoverningAgreementRef() {
        return governingAgreementRef;
    }

    /**
     * Sets the value of the governingAgreementRef property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setGoverningAgreementRef(String value) {
        this.governingAgreementRef = value;
    }

}
