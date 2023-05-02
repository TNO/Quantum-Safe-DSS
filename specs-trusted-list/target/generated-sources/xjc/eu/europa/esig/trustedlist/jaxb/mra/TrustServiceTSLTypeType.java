//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:29 PM CEST 
//


package eu.europa.esig.trustedlist.jaxb.mra;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;


/**
 * <p>Java class for TrustServiceTSLTypeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrustServiceTSLTypeType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}ServiceTypeIdentifier"/&gt;
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}AdditionalServiceInformation" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustServiceTSLTypeType", propOrder = {
    "serviceTypeIdentifier",
    "additionalServiceInformation"
})
public class TrustServiceTSLTypeType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "ServiceTypeIdentifier", namespace = "http://uri.etsi.org/02231/v2#", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String serviceTypeIdentifier;
    @XmlElement(name = "AdditionalServiceInformation", namespace = "http://uri.etsi.org/02231/v2#")
    protected AdditionalServiceInformationType additionalServiceInformation;

    /**
     * Gets the value of the serviceTypeIdentifier property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getServiceTypeIdentifier() {
        return serviceTypeIdentifier;
    }

    /**
     * Sets the value of the serviceTypeIdentifier property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setServiceTypeIdentifier(String value) {
        this.serviceTypeIdentifier = value;
    }

    /**
     * Gets the value of the additionalServiceInformation property.
     * 
     * @return
     *     possible object is
     *     {@link AdditionalServiceInformationType }
     *     
     */
    public AdditionalServiceInformationType getAdditionalServiceInformation() {
        return additionalServiceInformation;
    }

    /**
     * Sets the value of the additionalServiceInformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link AdditionalServiceInformationType }
     *     
     */
    public void setAdditionalServiceInformation(AdditionalServiceInformationType value) {
        this.additionalServiceInformation = value;
    }

}
