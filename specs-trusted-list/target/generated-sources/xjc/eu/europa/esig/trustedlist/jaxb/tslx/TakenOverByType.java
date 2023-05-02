//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:13 PM CEST 
//


package eu.europa.esig.trustedlist.jaxb.tslx;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;


/**
 * <p>Java class for TakenOverByType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TakenOverByType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="URI" type="{http://uri.etsi.org/02231/v2#}NonEmptyMultiLangURIType"/&gt;
 *         &lt;element name="TSPName" type="{http://uri.etsi.org/02231/v2#}InternationalNamesType"/&gt;
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}SchemeOperatorName"/&gt;
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}SchemeTerritory"/&gt;
 *         &lt;element name="OtherQualifier" type="{http://uri.etsi.org/02231/v2#}AnyType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TakenOverByType", propOrder = {
    "uri",
    "tspName",
    "schemeOperatorName",
    "schemeTerritory",
    "otherQualifier"
})
public class TakenOverByType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "URI", required = true)
    protected NonEmptyMultiLangURIType uri;
    @XmlElement(name = "TSPName", required = true)
    protected InternationalNamesType tspName;
    @XmlElement(name = "SchemeOperatorName", namespace = "http://uri.etsi.org/02231/v2#", required = true)
    protected InternationalNamesType schemeOperatorName;
    @XmlElement(name = "SchemeTerritory", namespace = "http://uri.etsi.org/02231/v2#", required = true)
    protected String schemeTerritory;
    @XmlElement(name = "OtherQualifier")
    protected List<AnyType> otherQualifier;

    /**
     * Gets the value of the uri property.
     * 
     * @return
     *     possible object is
     *     {@link NonEmptyMultiLangURIType }
     *     
     */
    public NonEmptyMultiLangURIType getURI() {
        return uri;
    }

    /**
     * Sets the value of the uri property.
     * 
     * @param value
     *     allowed object is
     *     {@link NonEmptyMultiLangURIType }
     *     
     */
    public void setURI(NonEmptyMultiLangURIType value) {
        this.uri = value;
    }

    /**
     * Gets the value of the tspName property.
     * 
     * @return
     *     possible object is
     *     {@link InternationalNamesType }
     *     
     */
    public InternationalNamesType getTSPName() {
        return tspName;
    }

    /**
     * Sets the value of the tspName property.
     * 
     * @param value
     *     allowed object is
     *     {@link InternationalNamesType }
     *     
     */
    public void setTSPName(InternationalNamesType value) {
        this.tspName = value;
    }

    /**
     * Gets the value of the schemeOperatorName property.
     * 
     * @return
     *     possible object is
     *     {@link InternationalNamesType }
     *     
     */
    public InternationalNamesType getSchemeOperatorName() {
        return schemeOperatorName;
    }

    /**
     * Sets the value of the schemeOperatorName property.
     * 
     * @param value
     *     allowed object is
     *     {@link InternationalNamesType }
     *     
     */
    public void setSchemeOperatorName(InternationalNamesType value) {
        this.schemeOperatorName = value;
    }

    /**
     * Gets the value of the schemeTerritory property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSchemeTerritory() {
        return schemeTerritory;
    }

    /**
     * Sets the value of the schemeTerritory property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSchemeTerritory(String value) {
        this.schemeTerritory = value;
    }

    /**
     * Gets the value of the otherQualifier property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the otherQualifier property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getOtherQualifier().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AnyType }
     * 
     * 
     */
    public List<AnyType> getOtherQualifier() {
        if (otherQualifier == null) {
            otherQualifier = new ArrayList<AnyType>();
        }
        return this.otherQualifier;
    }

}
