//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
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
 * <p>Java class for ObjectModifications complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObjectModifications"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="ExtensionChange" type="{http://dss.esig.europa.eu/validation/diagnostic}ObjectModification" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="SignatureOrFormFill" type="{http://dss.esig.europa.eu/validation/diagnostic}ObjectModification" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="AnnotationChange" type="{http://dss.esig.europa.eu/validation/diagnostic}ObjectModification" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Undefined" type="{http://dss.esig.europa.eu/validation/diagnostic}ObjectModification" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ObjectModifications", propOrder = {
    "extensionChanges",
    "signatureOrFormFill",
    "annotationChanges",
    "undefined"
})
public class XmlObjectModifications implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "ExtensionChange")
    protected List<XmlObjectModification> extensionChanges;
    @XmlElement(name = "SignatureOrFormFill")
    protected List<XmlObjectModification> signatureOrFormFill;
    @XmlElement(name = "AnnotationChange")
    protected List<XmlObjectModification> annotationChanges;
    @XmlElement(name = "Undefined")
    protected List<XmlObjectModification> undefined;

    /**
     * Gets the value of the extensionChanges property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the extensionChanges property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getExtensionChanges().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlObjectModification }
     * 
     * 
     */
    public List<XmlObjectModification> getExtensionChanges() {
        if (extensionChanges == null) {
            extensionChanges = new ArrayList<XmlObjectModification>();
        }
        return this.extensionChanges;
    }

    /**
     * Gets the value of the signatureOrFormFill property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the signatureOrFormFill property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSignatureOrFormFill().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlObjectModification }
     * 
     * 
     */
    public List<XmlObjectModification> getSignatureOrFormFill() {
        if (signatureOrFormFill == null) {
            signatureOrFormFill = new ArrayList<XmlObjectModification>();
        }
        return this.signatureOrFormFill;
    }

    /**
     * Gets the value of the annotationChanges property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the annotationChanges property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAnnotationChanges().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlObjectModification }
     * 
     * 
     */
    public List<XmlObjectModification> getAnnotationChanges() {
        if (annotationChanges == null) {
            annotationChanges = new ArrayList<XmlObjectModification>();
        }
        return this.annotationChanges;
    }

    /**
     * Gets the value of the undefined property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the undefined property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getUndefined().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlObjectModification }
     * 
     * 
     */
    public List<XmlObjectModification> getUndefined() {
        if (undefined == null) {
            undefined = new ArrayList<XmlObjectModification>();
        }
        return this.undefined;
    }

}
