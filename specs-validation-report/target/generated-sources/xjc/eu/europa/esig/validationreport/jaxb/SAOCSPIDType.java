//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:34 PM CEST 
//


package eu.europa.esig.validationreport.jaxb;

import java.io.Serializable;
import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.w3._2001.xmlschema.Adapter1;


/**
 * <p>Java class for SAOCSPIDType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SAOCSPIDType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="ProducedAt" type="{http://www.w3.org/2001/XMLSchema}dateTime"/&gt;
 *         &lt;choice&gt;
 *           &lt;element name="ResponderIDByName" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *           &lt;element name="ResponderIDByKey" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/&gt;
 *         &lt;/choice&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SAOCSPIDType", propOrder = {
    "producedAt",
    "responderIDByName",
    "responderIDByKey"
})
public class SAOCSPIDType implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "ProducedAt", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date producedAt;
    @XmlElement(name = "ResponderIDByName")
    protected String responderIDByName;
    @XmlElement(name = "ResponderIDByKey")
    protected byte[] responderIDByKey;

    /**
     * Gets the value of the producedAt property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getProducedAt() {
        return producedAt;
    }

    /**
     * Sets the value of the producedAt property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProducedAt(Date value) {
        this.producedAt = value;
    }

    /**
     * Gets the value of the responderIDByName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getResponderIDByName() {
        return responderIDByName;
    }

    /**
     * Sets the value of the responderIDByName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setResponderIDByName(String value) {
        this.responderIDByName = value;
    }

    /**
     * Gets the value of the responderIDByKey property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getResponderIDByKey() {
        return responderIDByKey;
    }

    /**
     * Sets the value of the responderIDByKey property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setResponderIDByKey(byte[] value) {
        this.responderIDByKey = value;
    }

}
