//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;


/**
 * <p>Java class for TimestampedObject complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TimestampedObject"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Token" use="required" type="{http://www.w3.org/2001/XMLSchema}IDREF" /&gt;
 *       &lt;attribute name="Category" use="required" type="{http://dss.esig.europa.eu/validation/diagnostic}TimestampedObjectType" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TimestampedObject")
public class XmlTimestampedObject implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlAttribute(name = "Token", required = true)
    @XmlIDREF
    @XmlSchemaType(name = "IDREF")
    protected XmlAbstractToken token;
    @XmlAttribute(name = "Category", required = true)
    @XmlJavaTypeAdapter(Adapter9 .class)
    protected TimestampedObjectType category;

    /**
     * Gets the value of the token property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public XmlAbstractToken getToken() {
        return token;
    }

    /**
     * Sets the value of the token property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setToken(XmlAbstractToken value) {
        this.token = value;
    }

    /**
     * Gets the value of the category property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public TimestampedObjectType getCategory() {
        return category;
    }

    /**
     * Sets the value of the category property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCategory(TimestampedObjectType value) {
        this.category = value;
    }

}
