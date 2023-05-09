//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:56 PM CEST 
//


package eu.europa.esig.dss.detailedreport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for DetailedReport complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DetailedReport"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;sequence maxOccurs="unbounded" minOccurs="0"&gt;
 *           &lt;choice&gt;
 *             &lt;element name="Signature" type="{http://dss.esig.europa.eu/validation/detailed-report}Signature"/&gt;
 *             &lt;element name="Timestamp" type="{http://dss.esig.europa.eu/validation/detailed-report}Timestamp"/&gt;
 *             &lt;element name="Certificate" type="{http://dss.esig.europa.eu/validation/detailed-report}Certificate"/&gt;
 *           &lt;/choice&gt;
 *         &lt;/sequence&gt;
 *         &lt;element name="BasicBuildingBlocks" type="{http://dss.esig.europa.eu/validation/detailed-report}BasicBuildingBlocks" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="TLAnalysis" type="{http://dss.esig.europa.eu/validation/detailed-report}TLAnalysis" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Semantic" type="{http://dss.esig.europa.eu/validation/detailed-report}Semantic" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="ValidationTime" type="{http://www.w3.org/2001/XMLSchema}dateTime" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DetailedReport", propOrder = {
    "signatureOrTimestampOrCertificate",
    "basicBuildingBlocks",
    "tlAnalysis",
    "semantic"
})
public class XmlDetailedReport
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElements({
        @XmlElement(name = "Signature", type = XmlSignature.class),
        @XmlElement(name = "Timestamp", type = XmlTimestamp.class),
        @XmlElement(name = "Certificate", type = XmlCertificate.class)
    })
    protected List<Serializable> signatureOrTimestampOrCertificate;
    @XmlElement(name = "BasicBuildingBlocks")
    protected List<XmlBasicBuildingBlocks> basicBuildingBlocks;
    @XmlElement(name = "TLAnalysis")
    protected List<XmlTLAnalysis> tlAnalysis;
    @XmlElement(name = "Semantic")
    protected List<XmlSemantic> semantic;
    @XmlAttribute(name = "ValidationTime")
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date validationTime;

    /**
     * Gets the value of the signatureOrTimestampOrCertificate property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the signatureOrTimestampOrCertificate property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSignatureOrTimestampOrCertificate().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlCertificate }
     * {@link XmlSignature }
     * {@link XmlTimestamp }
     * 
     * 
     */
    public List<Serializable> getSignatureOrTimestampOrCertificate() {
        if (signatureOrTimestampOrCertificate == null) {
            signatureOrTimestampOrCertificate = new ArrayList<Serializable>();
        }
        return this.signatureOrTimestampOrCertificate;
    }

    /**
     * Gets the value of the basicBuildingBlocks property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the basicBuildingBlocks property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getBasicBuildingBlocks().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlBasicBuildingBlocks }
     * 
     * 
     */
    public List<XmlBasicBuildingBlocks> getBasicBuildingBlocks() {
        if (basicBuildingBlocks == null) {
            basicBuildingBlocks = new ArrayList<XmlBasicBuildingBlocks>();
        }
        return this.basicBuildingBlocks;
    }

    /**
     * Gets the value of the tlAnalysis property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the tlAnalysis property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTLAnalysis().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlTLAnalysis }
     * 
     * 
     */
    public List<XmlTLAnalysis> getTLAnalysis() {
        if (tlAnalysis == null) {
            tlAnalysis = new ArrayList<XmlTLAnalysis>();
        }
        return this.tlAnalysis;
    }

    /**
     * Gets the value of the semantic property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the semantic property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSemantic().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlSemantic }
     * 
     * 
     */
    public List<XmlSemantic> getSemantic() {
        if (semantic == null) {
            semantic = new ArrayList<XmlSemantic>();
        }
        return this.semantic;
    }

    /**
     * Gets the value of the validationTime property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getValidationTime() {
        return validationTime;
    }

    /**
     * Sets the value of the validationTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setValidationTime(Date value) {
        this.validationTime = value;
    }

}
