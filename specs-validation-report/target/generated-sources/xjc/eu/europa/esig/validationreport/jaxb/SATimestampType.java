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
 * <p>Java class for SATimestampType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SATimestampType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="TimeStampValue" type="{http://www.w3.org/2001/XMLSchema}dateTime"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SATimestampType", propOrder = {
    "timeStampValue"
})
public class SATimestampType
    extends AttributeBaseType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "TimeStampValue", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date timeStampValue;

    /**
     * Gets the value of the timeStampValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getTimeStampValue() {
        return timeStampValue;
    }

    /**
     * Sets the value of the timeStampValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTimeStampValue(Date value) {
        this.timeStampValue = value;
    }

}