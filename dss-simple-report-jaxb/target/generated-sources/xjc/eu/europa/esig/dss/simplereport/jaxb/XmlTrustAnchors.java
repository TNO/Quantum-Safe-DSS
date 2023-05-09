//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:59 PM CEST 
//


package eu.europa.esig.dss.simplereport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TrustAnchors complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrustAnchors"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="TrustAnchor" type="{http://dss.esig.europa.eu/validation/simple-report}TrustAnchor" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustAnchors", propOrder = {
    "trustAnchor"
})
public class XmlTrustAnchors
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "TrustAnchor")
    protected List<XmlTrustAnchor> trustAnchor;

    /**
     * Gets the value of the trustAnchor property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the trustAnchor property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTrustAnchor().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlTrustAnchor }
     * 
     * 
     */
    public List<XmlTrustAnchor> getTrustAnchor() {
        if (trustAnchor == null) {
            trustAnchor = new ArrayList<XmlTrustAnchor>();
        }
        return this.trustAnchor;
    }

}