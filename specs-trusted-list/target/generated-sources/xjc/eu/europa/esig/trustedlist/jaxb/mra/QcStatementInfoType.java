//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:13 PM CEST 
//


package eu.europa.esig.trustedlist.jaxb.mra;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import eu.europa.esig.xades.jaxb.xades132.ObjectIdentifierType;


/**
 * <p>Java class for QcStatementInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="QcStatementInfoType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;choice&gt;
 *         &lt;element ref="{http://ec.europa.eu/tools/lotl/mra/schema/v2#}QcType"/&gt;
 *         &lt;element ref="{http://ec.europa.eu/tools/lotl/mra/schema/v2#}QcCClegislation"/&gt;
 *       &lt;/choice&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "QcStatementInfoType", propOrder = {
    "qcType",
    "qcCClegislation"
})
public class QcStatementInfoType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "QcType")
    protected ObjectIdentifierType qcType;
    @XmlElement(name = "QcCClegislation")
    protected String qcCClegislation;

    /**
     * Gets the value of the qcType property.
     * 
     * @return
     *     possible object is
     *     {@link ObjectIdentifierType }
     *     
     */
    public ObjectIdentifierType getQcType() {
        return qcType;
    }

    /**
     * Sets the value of the qcType property.
     * 
     * @param value
     *     allowed object is
     *     {@link ObjectIdentifierType }
     *     
     */
    public void setQcType(ObjectIdentifierType value) {
        this.qcType = value;
    }

    /**
     * Gets the value of the qcCClegislation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getQcCClegislation() {
        return qcCClegislation;
    }

    /**
     * Sets the value of the qcCClegislation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setQcCClegislation(String value) {
        this.qcCClegislation = value;
    }

}
