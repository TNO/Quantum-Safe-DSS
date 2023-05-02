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
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SADSSType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SADSSType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Certs" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *         &lt;element name="CRLs" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *         &lt;element name="OCSPs" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SADSSType", propOrder = {
    "certs",
    "crLs",
    "ocsPs"
})
public class SADSSType
    extends AttributeBaseType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Certs")
    protected VOReferenceType certs;
    @XmlElement(name = "CRLs")
    protected VOReferenceType crLs;
    @XmlElement(name = "OCSPs")
    protected VOReferenceType ocsPs;

    /**
     * Gets the value of the certs property.
     * 
     * @return
     *     possible object is
     *     {@link VOReferenceType }
     *     
     */
    public VOReferenceType getCerts() {
        return certs;
    }

    /**
     * Sets the value of the certs property.
     * 
     * @param value
     *     allowed object is
     *     {@link VOReferenceType }
     *     
     */
    public void setCerts(VOReferenceType value) {
        this.certs = value;
    }

    /**
     * Gets the value of the crLs property.
     * 
     * @return
     *     possible object is
     *     {@link VOReferenceType }
     *     
     */
    public VOReferenceType getCRLs() {
        return crLs;
    }

    /**
     * Sets the value of the crLs property.
     * 
     * @param value
     *     allowed object is
     *     {@link VOReferenceType }
     *     
     */
    public void setCRLs(VOReferenceType value) {
        this.crLs = value;
    }

    /**
     * Gets the value of the ocsPs property.
     * 
     * @return
     *     possible object is
     *     {@link VOReferenceType }
     *     
     */
    public VOReferenceType getOCSPs() {
        return ocsPs;
    }

    /**
     * Sets the value of the ocsPs property.
     * 
     * @param value
     *     allowed object is
     *     {@link VOReferenceType }
     *     
     */
    public void setOCSPs(VOReferenceType value) {
        this.ocsPs = value;
    }

}
