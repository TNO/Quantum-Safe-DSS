//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:50 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TrustedServiceProvider complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrustedServiceProvider"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="TSPNames"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="TSPName" type="{http://dss.esig.europa.eu/validation/diagnostic}LangAndValue" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="TSPTradeNames" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="TSPTradeName" type="{http://dss.esig.europa.eu/validation/diagnostic}LangAndValue" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="TSPRegistrationIdentifiers" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="TSPRegistrationIdentifier" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="TrustedServices"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="TrustedService" type="{http://dss.esig.europa.eu/validation/diagnostic}TrustedService" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="TL" use="required" type="{http://www.w3.org/2001/XMLSchema}IDREF" /&gt;
 *       &lt;attribute name="LOTL" type="{http://www.w3.org/2001/XMLSchema}IDREF" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustedServiceProvider", propOrder = {
    "tspNames",
    "tspTradeNames",
    "tspRegistrationIdentifiers",
    "trustedServices"
})
public class XmlTrustedServiceProvider implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElementWrapper(name = "TSPNames", required = true)
    @XmlElement(name = "TSPName", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
    protected List<XmlLangAndValue> tspNames;
    @XmlElementWrapper(name = "TSPTradeNames")
    @XmlElement(name = "TSPTradeName", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
    protected List<XmlLangAndValue> tspTradeNames;
    @XmlElementWrapper(name = "TSPRegistrationIdentifiers")
    @XmlElement(name = "TSPRegistrationIdentifier", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
    protected List<String> tspRegistrationIdentifiers;
    @XmlElementWrapper(name = "TrustedServices", required = true)
    @XmlElement(name = "TrustedService", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
    protected List<XmlTrustedService> trustedServices;
    @XmlAttribute(name = "TL", required = true)
    @XmlIDREF
    @XmlSchemaType(name = "IDREF")
    protected eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList tl;
    @XmlAttribute(name = "LOTL")
    @XmlIDREF
    @XmlSchemaType(name = "IDREF")
    protected eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList lotl;

    /**
     * Gets the value of the tl property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList getTL() {
        return tl;
    }

    /**
     * Sets the value of the tl property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setTL(eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList value) {
        this.tl = value;
    }

    /**
     * Gets the value of the lotl property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList getLOTL() {
        return lotl;
    }

    /**
     * Sets the value of the lotl property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setLOTL(eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList value) {
        this.lotl = value;
    }

    public List<XmlLangAndValue> getTSPNames() {
        if (tspNames == null) {
            tspNames = new ArrayList<XmlLangAndValue>();
        }
        return tspNames;
    }

    public void setTSPNames(List<XmlLangAndValue> tspNames) {
        this.tspNames = tspNames;
    }

    public List<XmlLangAndValue> getTSPTradeNames() {
        if (tspTradeNames == null) {
            tspTradeNames = new ArrayList<XmlLangAndValue>();
        }
        return tspTradeNames;
    }

    public void setTSPTradeNames(List<XmlLangAndValue> tspTradeNames) {
        this.tspTradeNames = tspTradeNames;
    }

    public List<String> getTSPRegistrationIdentifiers() {
        if (tspRegistrationIdentifiers == null) {
            tspRegistrationIdentifiers = new ArrayList<String>();
        }
        return tspRegistrationIdentifiers;
    }

    public void setTSPRegistrationIdentifiers(List<String> tspRegistrationIdentifiers) {
        this.tspRegistrationIdentifiers = tspRegistrationIdentifiers;
    }

    public List<XmlTrustedService> getTrustedServices() {
        if (trustedServices == null) {
            trustedServices = new ArrayList<XmlTrustedService>();
        }
        return trustedServices;
    }

    public void setTrustedServices(List<XmlTrustedService> trustedServices) {
        this.trustedServices = trustedServices;
    }

}
