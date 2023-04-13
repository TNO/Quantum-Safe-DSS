//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:51 PM CET 
//


package eu.europa.esig.dss.detailedreport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlList;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CRS complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CRS"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/detailed-report}ConstraintsConclusion"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="RAC" type="{http://dss.esig.europa.eu/validation/detailed-report}RAC" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="AcceptableRevocationId" minOccurs="0"&gt;
 *           &lt;simpleType&gt;
 *             &lt;list itemType="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *           &lt;/simpleType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="LatestAcceptableRevocationId" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CRS", propOrder = {
    "rac",
    "acceptableRevocationId"
})
public class XmlCRS
    extends XmlConstraintsConclusion
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "RAC")
    protected List<XmlRAC> rac;
    @XmlList
    @XmlElement(name = "AcceptableRevocationId")
    protected List<String> acceptableRevocationId;
    @XmlAttribute(name = "Id")
    protected String id;
    @XmlAttribute(name = "LatestAcceptableRevocationId")
    protected String latestAcceptableRevocationId;

    /**
     * Gets the value of the rac property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the rac property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRAC().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlRAC }
     * 
     * 
     */
    public List<XmlRAC> getRAC() {
        if (rac == null) {
            rac = new ArrayList<XmlRAC>();
        }
        return this.rac;
    }

    /**
     * Gets the value of the acceptableRevocationId property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the acceptableRevocationId property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAcceptableRevocationId().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getAcceptableRevocationId() {
        if (acceptableRevocationId == null) {
            acceptableRevocationId = new ArrayList<String>();
        }
        return this.acceptableRevocationId;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the latestAcceptableRevocationId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLatestAcceptableRevocationId() {
        return latestAcceptableRevocationId;
    }

    /**
     * Sets the value of the latestAcceptableRevocationId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLatestAcceptableRevocationId(String value) {
        this.latestAcceptableRevocationId = value;
    }

}
