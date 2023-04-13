//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:43 PM CET 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for MRACertificateMapping complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="MRACertificateMapping"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="EnactedTrustServiceLegalIdentifier" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="OriginalThirdCountryMapping" type="{http://dss.esig.europa.eu/validation/diagnostic}OriginalThirdCountryQcStatementsMapping"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "MRACertificateMapping", propOrder = {
    "enactedTrustServiceLegalIdentifier",
    "originalThirdCountryMapping"
})
public class XmlMRACertificateMapping implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "EnactedTrustServiceLegalIdentifier", required = true)
    protected String enactedTrustServiceLegalIdentifier;
    @XmlElement(name = "OriginalThirdCountryMapping", required = true)
    protected XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping;

    /**
     * Gets the value of the enactedTrustServiceLegalIdentifier property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEnactedTrustServiceLegalIdentifier() {
        return enactedTrustServiceLegalIdentifier;
    }

    /**
     * Sets the value of the enactedTrustServiceLegalIdentifier property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEnactedTrustServiceLegalIdentifier(String value) {
        this.enactedTrustServiceLegalIdentifier = value;
    }

    /**
     * Gets the value of the originalThirdCountryMapping property.
     * 
     * @return
     *     possible object is
     *     {@link XmlOriginalThirdCountryQcStatementsMapping }
     *     
     */
    public XmlOriginalThirdCountryQcStatementsMapping getOriginalThirdCountryMapping() {
        return originalThirdCountryMapping;
    }

    /**
     * Sets the value of the originalThirdCountryMapping property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlOriginalThirdCountryQcStatementsMapping }
     *     
     */
    public void setOriginalThirdCountryMapping(XmlOriginalThirdCountryQcStatementsMapping value) {
        this.originalThirdCountryMapping = value;
    }

}
