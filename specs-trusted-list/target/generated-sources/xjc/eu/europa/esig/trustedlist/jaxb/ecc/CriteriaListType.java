//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:14 PM CET 
//


package eu.europa.esig.trustedlist.jaxb.ecc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.trustedlist.enums.Assert;
import eu.europa.esig.xades.jaxb.xades132.AnyType;


/**
 * <p>Java class for CriteriaListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CriteriaListType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="KeyUsage" type="{http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#}KeyUsageType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="PolicySet" type="{http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#}PoliciesListType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="CriteriaList" type="{http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#}CriteriaListType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="otherCriteriaList" type="{http://uri.etsi.org/01903/v1.3.2#}AnyType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="assert"&gt;
 *         &lt;simpleType&gt;
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *             &lt;enumeration value="all"/&gt;
 *             &lt;enumeration value="atLeastOne"/&gt;
 *             &lt;enumeration value="none"/&gt;
 *           &lt;/restriction&gt;
 *         &lt;/simpleType&gt;
 *       &lt;/attribute&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CriteriaListType", propOrder = {
    "keyUsage",
    "policySet",
    "criteriaList",
    "description",
    "otherCriteriaList"
})
public class CriteriaListType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "KeyUsage")
    protected List<KeyUsageType> keyUsage;
    @XmlElement(name = "PolicySet")
    protected List<PoliciesListType> policySet;
    @XmlElement(name = "CriteriaList")
    protected List<CriteriaListType> criteriaList;
    @XmlElement(name = "Description")
    protected String description;
    protected AnyType otherCriteriaList;
    @XmlAttribute(name = "assert")
    @XmlJavaTypeAdapter(Adapter2 .class)
    protected Assert _assert;

    /**
     * Gets the value of the keyUsage property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the keyUsage property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getKeyUsage().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link KeyUsageType }
     * 
     * 
     */
    public List<KeyUsageType> getKeyUsage() {
        if (keyUsage == null) {
            keyUsage = new ArrayList<KeyUsageType>();
        }
        return this.keyUsage;
    }

    /**
     * Gets the value of the policySet property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the policySet property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPolicySet().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PoliciesListType }
     * 
     * 
     */
    public List<PoliciesListType> getPolicySet() {
        if (policySet == null) {
            policySet = new ArrayList<PoliciesListType>();
        }
        return this.policySet;
    }

    /**
     * Gets the value of the criteriaList property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the criteriaList property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCriteriaList().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link CriteriaListType }
     * 
     * 
     */
    public List<CriteriaListType> getCriteriaList() {
        if (criteriaList == null) {
            criteriaList = new ArrayList<CriteriaListType>();
        }
        return this.criteriaList;
    }

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

    /**
     * Gets the value of the otherCriteriaList property.
     * 
     * @return
     *     possible object is
     *     {@link AnyType }
     *     
     */
    public AnyType getOtherCriteriaList() {
        return otherCriteriaList;
    }

    /**
     * Sets the value of the otherCriteriaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link AnyType }
     *     
     */
    public void setOtherCriteriaList(AnyType value) {
        this.otherCriteriaList = value;
    }

    /**
     * Gets the value of the assert property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Assert getAssert() {
        return _assert;
    }

    /**
     * Sets the value of the assert property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAssert(Assert value) {
        this._assert = value;
    }

}
