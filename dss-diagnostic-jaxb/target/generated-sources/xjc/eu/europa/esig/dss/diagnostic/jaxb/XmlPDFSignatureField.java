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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PDFSignatureField complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFSignatureField"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="SigFieldLock" type="{http://dss.esig.europa.eu/validation/diagnostic}PDFLockDictionary" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="name" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFSignatureField", propOrder = {
    "sigFieldLock"
})
public class XmlPDFSignatureField implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "SigFieldLock")
    protected XmlPDFLockDictionary sigFieldLock;
    @XmlAttribute(name = "name")
    protected String name;

    /**
     * Gets the value of the sigFieldLock property.
     * 
     * @return
     *     possible object is
     *     {@link XmlPDFLockDictionary }
     *     
     */
    public XmlPDFLockDictionary getSigFieldLock() {
        return sigFieldLock;
    }

    /**
     * Sets the value of the sigFieldLock property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlPDFLockDictionary }
     *     
     */
    public void setSigFieldLock(XmlPDFLockDictionary value) {
        this.sigFieldLock = value;
    }

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setName(String value) {
        this.name = value;
    }

}
