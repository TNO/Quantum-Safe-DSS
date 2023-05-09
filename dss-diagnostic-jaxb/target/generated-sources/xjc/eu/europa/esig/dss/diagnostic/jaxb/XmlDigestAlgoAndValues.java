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
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DigestAlgoAndValues complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DigestAlgoAndValues"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="DigestAlgoAndValue" type="{http://dss.esig.europa.eu/validation/diagnostic}DigestAlgoAndValue" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DigestAlgoAndValues", propOrder = {
    "digestAlgoAndValue"
})
public class XmlDigestAlgoAndValues implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "DigestAlgoAndValue")
    protected List<XmlDigestAlgoAndValue> digestAlgoAndValue;

    /**
     * Gets the value of the digestAlgoAndValue property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the digestAlgoAndValue property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDigestAlgoAndValue().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlDigestAlgoAndValue }
     * 
     * 
     */
    public List<XmlDigestAlgoAndValue> getDigestAlgoAndValue() {
        if (digestAlgoAndValue == null) {
            digestAlgoAndValue = new ArrayList<XmlDigestAlgoAndValue>();
        }
        return this.digestAlgoAndValue;
    }

}