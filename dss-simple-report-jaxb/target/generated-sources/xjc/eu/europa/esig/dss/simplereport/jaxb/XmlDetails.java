//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:33 PM CEST 
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
 * <p>Java class for Details complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Details"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Error" type="{http://dss.esig.europa.eu/validation/simple-report}Message" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Warning" type="{http://dss.esig.europa.eu/validation/simple-report}Message" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Info" type="{http://dss.esig.europa.eu/validation/simple-report}Message" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Details", propOrder = {
    "error",
    "warning",
    "info"
})
public class XmlDetails
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Error")
    protected List<XmlMessage> error;
    @XmlElement(name = "Warning")
    protected List<XmlMessage> warning;
    @XmlElement(name = "Info")
    protected List<XmlMessage> info;

    /**
     * Gets the value of the error property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the error property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getError().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlMessage }
     * 
     * 
     */
    public List<XmlMessage> getError() {
        if (error == null) {
            error = new ArrayList<XmlMessage>();
        }
        return this.error;
    }

    /**
     * Gets the value of the warning property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the warning property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getWarning().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlMessage }
     * 
     * 
     */
    public List<XmlMessage> getWarning() {
        if (warning == null) {
            warning = new ArrayList<XmlMessage>();
        }
        return this.warning;
    }

    /**
     * Gets the value of the info property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the info property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getInfo().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlMessage }
     * 
     * 
     */
    public List<XmlMessage> getInfo() {
        if (info == null) {
            info = new ArrayList<XmlMessage>();
        }
        return this.info;
    }

}
