//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:51 PM CET 
//


package eu.europa.esig.dss.detailedreport.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Constraint complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Constraint"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Name" type="{http://dss.esig.europa.eu/validation/detailed-report}Message"/&gt;
 *         &lt;element name="Status" type="{http://dss.esig.europa.eu/validation/detailed-report}Status"/&gt;
 *         &lt;element name="Error" type="{http://dss.esig.europa.eu/validation/detailed-report}Message" minOccurs="0"/&gt;
 *         &lt;element name="Warning" type="{http://dss.esig.europa.eu/validation/detailed-report}Message" minOccurs="0"/&gt;
 *         &lt;element name="Info" type="{http://dss.esig.europa.eu/validation/detailed-report}Message" minOccurs="0"/&gt;
 *         &lt;element name="AdditionalInfo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="BlockType" type="{http://dss.esig.europa.eu/validation/detailed-report}BlockType" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Constraint", propOrder = {
    "name",
    "status",
    "error",
    "warning",
    "info",
    "additionalInfo"
})
public class XmlConstraint
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Name", required = true)
    protected XmlMessage name;
    @XmlElement(name = "Status", required = true)
    @XmlSchemaType(name = "string")
    protected XmlStatus status;
    @XmlElement(name = "Error")
    protected XmlMessage error;
    @XmlElement(name = "Warning")
    protected XmlMessage warning;
    @XmlElement(name = "Info")
    protected XmlMessage info;
    @XmlElement(name = "AdditionalInfo")
    protected String additionalInfo;
    @XmlAttribute(name = "Id")
    protected String id;
    @XmlAttribute(name = "BlockType")
    protected XmlBlockType blockType;

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link XmlMessage }
     *     
     */
    public XmlMessage getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlMessage }
     *     
     */
    public void setName(XmlMessage value) {
        this.name = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link XmlStatus }
     *     
     */
    public XmlStatus getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlStatus }
     *     
     */
    public void setStatus(XmlStatus value) {
        this.status = value;
    }

    /**
     * Gets the value of the error property.
     * 
     * @return
     *     possible object is
     *     {@link XmlMessage }
     *     
     */
    public XmlMessage getError() {
        return error;
    }

    /**
     * Sets the value of the error property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlMessage }
     *     
     */
    public void setError(XmlMessage value) {
        this.error = value;
    }

    /**
     * Gets the value of the warning property.
     * 
     * @return
     *     possible object is
     *     {@link XmlMessage }
     *     
     */
    public XmlMessage getWarning() {
        return warning;
    }

    /**
     * Sets the value of the warning property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlMessage }
     *     
     */
    public void setWarning(XmlMessage value) {
        this.warning = value;
    }

    /**
     * Gets the value of the info property.
     * 
     * @return
     *     possible object is
     *     {@link XmlMessage }
     *     
     */
    public XmlMessage getInfo() {
        return info;
    }

    /**
     * Sets the value of the info property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlMessage }
     *     
     */
    public void setInfo(XmlMessage value) {
        this.info = value;
    }

    /**
     * Gets the value of the additionalInfo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAdditionalInfo() {
        return additionalInfo;
    }

    /**
     * Sets the value of the additionalInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAdditionalInfo(String value) {
        this.additionalInfo = value;
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
     * Gets the value of the blockType property.
     * 
     * @return
     *     possible object is
     *     {@link XmlBlockType }
     *     
     */
    public XmlBlockType getBlockType() {
        return blockType;
    }

    /**
     * Sets the value of the blockType property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlBlockType }
     *     
     */
    public void setBlockType(XmlBlockType value) {
        this.blockType = value;
    }

}
