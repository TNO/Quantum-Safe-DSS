//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;


/**
 * <p>Java class for FoundRevocation complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="FoundRevocation"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Type" type="{http://dss.esig.europa.eu/validation/diagnostic}RevocationType"/&gt;
 *         &lt;element name="Origin" type="{http://dss.esig.europa.eu/validation/diagnostic}RevocationOriginType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="RevocationRef" type="{http://dss.esig.europa.eu/validation/diagnostic}RevocationRef" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "FoundRevocation", propOrder = {
    "type",
    "origins",
    "revocationRefs"
})
@XmlSeeAlso({
    XmlRelatedRevocation.class,
    XmlOrphanRevocation.class
})
public abstract class XmlFoundRevocation implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Type", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter20 .class)
    protected RevocationType type;
    @XmlElement(name = "Origin", type = String.class)
    @XmlJavaTypeAdapter(Adapter21 .class)
    protected List<RevocationOrigin> origins;
    @XmlElement(name = "RevocationRef")
    protected List<XmlRevocationRef> revocationRefs;

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public RevocationType getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(RevocationType value) {
        this.type = value;
    }

    /**
     * Gets the value of the origins property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the origins property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getOrigins().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<RevocationOrigin> getOrigins() {
        if (origins == null) {
            origins = new ArrayList<RevocationOrigin>();
        }
        return this.origins;
    }

    /**
     * Gets the value of the revocationRefs property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the revocationRefs property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRevocationRefs().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlRevocationRef }
     * 
     * 
     */
    public List<XmlRevocationRef> getRevocationRefs() {
        if (revocationRefs == null) {
            revocationRefs = new ArrayList<XmlRevocationRef>();
        }
        return this.revocationRefs;
    }

}
