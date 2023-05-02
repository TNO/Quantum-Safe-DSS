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
 * <p>Java class for PDFRevision complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFRevision"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="SignatureField" type="{http://dss.esig.europa.eu/validation/diagnostic}PDFSignatureField" maxOccurs="unbounded"/&gt;
 *         &lt;element name="PDFSignatureDictionary" type="{http://dss.esig.europa.eu/validation/diagnostic}PDFSignatureDictionary"/&gt;
 *         &lt;element name="ModificationDetection" type="{http://dss.esig.europa.eu/validation/diagnostic}ModificationDetection" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFRevision", propOrder = {
    "fields",
    "pdfSignatureDictionary",
    "modificationDetection"
})
public class XmlPDFRevision implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "SignatureField", required = true)
    protected List<XmlPDFSignatureField> fields;
    @XmlElement(name = "PDFSignatureDictionary", required = true)
    protected XmlPDFSignatureDictionary pdfSignatureDictionary;
    @XmlElement(name = "ModificationDetection")
    protected XmlModificationDetection modificationDetection;

    /**
     * Gets the value of the fields property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the fields property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getFields().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlPDFSignatureField }
     * 
     * 
     */
    public List<XmlPDFSignatureField> getFields() {
        if (fields == null) {
            fields = new ArrayList<XmlPDFSignatureField>();
        }
        return this.fields;
    }

    /**
     * Gets the value of the pdfSignatureDictionary property.
     * 
     * @return
     *     possible object is
     *     {@link XmlPDFSignatureDictionary }
     *     
     */
    public XmlPDFSignatureDictionary getPDFSignatureDictionary() {
        return pdfSignatureDictionary;
    }

    /**
     * Sets the value of the pdfSignatureDictionary property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlPDFSignatureDictionary }
     *     
     */
    public void setPDFSignatureDictionary(XmlPDFSignatureDictionary value) {
        this.pdfSignatureDictionary = value;
    }

    /**
     * Gets the value of the modificationDetection property.
     * 
     * @return
     *     possible object is
     *     {@link XmlModificationDetection }
     *     
     */
    public XmlModificationDetection getModificationDetection() {
        return modificationDetection;
    }

    /**
     * Sets the value of the modificationDetection property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlModificationDetection }
     *     
     */
    public void setModificationDetection(XmlModificationDetection value) {
        this.modificationDetection = value;
    }

}
