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
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.Context;


/**
 * <p>Java class for BasicBuildingBlocks complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BasicBuildingBlocks"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="FC" type="{http://dss.esig.europa.eu/validation/detailed-report}FC" minOccurs="0"/&gt;
 *         &lt;element name="ISC" type="{http://dss.esig.europa.eu/validation/detailed-report}ISC" minOccurs="0"/&gt;
 *         &lt;element name="VCI" type="{http://dss.esig.europa.eu/validation/detailed-report}VCI" minOccurs="0"/&gt;
 *         &lt;element name="XCV" type="{http://dss.esig.europa.eu/validation/detailed-report}XCV" minOccurs="0"/&gt;
 *         &lt;element name="CV" type="{http://dss.esig.europa.eu/validation/detailed-report}CV" minOccurs="0"/&gt;
 *         &lt;element name="SAV" type="{http://dss.esig.europa.eu/validation/detailed-report}SAV" minOccurs="0"/&gt;
 *         &lt;element name="PSV" type="{http://dss.esig.europa.eu/validation/detailed-report}PSV" minOccurs="0"/&gt;
 *         &lt;element name="PSV_CRS" type="{http://dss.esig.europa.eu/validation/detailed-report}CRS" minOccurs="0"/&gt;
 *         &lt;element name="PCV" type="{http://dss.esig.europa.eu/validation/detailed-report}PCV" minOccurs="0"/&gt;
 *         &lt;element name="VTS" type="{http://dss.esig.europa.eu/validation/detailed-report}VTS" minOccurs="0"/&gt;
 *         &lt;element name="CertificateChain" type="{http://dss.esig.europa.eu/validation/detailed-report}CertificateChain" minOccurs="0"/&gt;
 *         &lt;element name="Conclusion" type="{http://dss.esig.europa.eu/validation/detailed-report}Conclusion"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" use="required" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="Type" use="required" type="{http://dss.esig.europa.eu/validation/detailed-report}Context" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BasicBuildingBlocks", propOrder = {
    "fc",
    "isc",
    "vci",
    "xcv",
    "cv",
    "sav",
    "psv",
    "psvcrs",
    "pcv",
    "vts",
    "certificateChain",
    "conclusion"
})
public class XmlBasicBuildingBlocks
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "FC")
    protected XmlFC fc;
    @XmlElement(name = "ISC")
    protected XmlISC isc;
    @XmlElement(name = "VCI")
    protected XmlVCI vci;
    @XmlElement(name = "XCV")
    protected XmlXCV xcv;
    @XmlElement(name = "CV")
    protected XmlCV cv;
    @XmlElement(name = "SAV")
    protected XmlSAV sav;
    @XmlElement(name = "PSV")
    protected XmlPSV psv;
    @XmlElement(name = "PSV_CRS")
    protected XmlCRS psvcrs;
    @XmlElement(name = "PCV")
    protected XmlPCV pcv;
    @XmlElement(name = "VTS")
    protected XmlVTS vts;
    @XmlElement(name = "CertificateChain")
    protected XmlCertificateChain certificateChain;
    @XmlElement(name = "Conclusion", required = true)
    protected XmlConclusion conclusion;
    @XmlAttribute(name = "Id", required = true)
    protected String id;
    @XmlAttribute(name = "Type", required = true)
    @XmlJavaTypeAdapter(Adapter7 .class)
    protected Context type;

    /**
     * Gets the value of the fc property.
     * 
     * @return
     *     possible object is
     *     {@link XmlFC }
     *     
     */
    public XmlFC getFC() {
        return fc;
    }

    /**
     * Sets the value of the fc property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlFC }
     *     
     */
    public void setFC(XmlFC value) {
        this.fc = value;
    }

    /**
     * Gets the value of the isc property.
     * 
     * @return
     *     possible object is
     *     {@link XmlISC }
     *     
     */
    public XmlISC getISC() {
        return isc;
    }

    /**
     * Sets the value of the isc property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlISC }
     *     
     */
    public void setISC(XmlISC value) {
        this.isc = value;
    }

    /**
     * Gets the value of the vci property.
     * 
     * @return
     *     possible object is
     *     {@link XmlVCI }
     *     
     */
    public XmlVCI getVCI() {
        return vci;
    }

    /**
     * Sets the value of the vci property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlVCI }
     *     
     */
    public void setVCI(XmlVCI value) {
        this.vci = value;
    }

    /**
     * Gets the value of the xcv property.
     * 
     * @return
     *     possible object is
     *     {@link XmlXCV }
     *     
     */
    public XmlXCV getXCV() {
        return xcv;
    }

    /**
     * Sets the value of the xcv property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlXCV }
     *     
     */
    public void setXCV(XmlXCV value) {
        this.xcv = value;
    }

    /**
     * Gets the value of the cv property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCV }
     *     
     */
    public XmlCV getCV() {
        return cv;
    }

    /**
     * Sets the value of the cv property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCV }
     *     
     */
    public void setCV(XmlCV value) {
        this.cv = value;
    }

    /**
     * Gets the value of the sav property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSAV }
     *     
     */
    public XmlSAV getSAV() {
        return sav;
    }

    /**
     * Sets the value of the sav property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSAV }
     *     
     */
    public void setSAV(XmlSAV value) {
        this.sav = value;
    }

    /**
     * Gets the value of the psv property.
     * 
     * @return
     *     possible object is
     *     {@link XmlPSV }
     *     
     */
    public XmlPSV getPSV() {
        return psv;
    }

    /**
     * Sets the value of the psv property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlPSV }
     *     
     */
    public void setPSV(XmlPSV value) {
        this.psv = value;
    }

    /**
     * Gets the value of the psvcrs property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCRS }
     *     
     */
    public XmlCRS getPSVCRS() {
        return psvcrs;
    }

    /**
     * Sets the value of the psvcrs property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCRS }
     *     
     */
    public void setPSVCRS(XmlCRS value) {
        this.psvcrs = value;
    }

    /**
     * Gets the value of the pcv property.
     * 
     * @return
     *     possible object is
     *     {@link XmlPCV }
     *     
     */
    public XmlPCV getPCV() {
        return pcv;
    }

    /**
     * Sets the value of the pcv property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlPCV }
     *     
     */
    public void setPCV(XmlPCV value) {
        this.pcv = value;
    }

    /**
     * Gets the value of the vts property.
     * 
     * @return
     *     possible object is
     *     {@link XmlVTS }
     *     
     */
    public XmlVTS getVTS() {
        return vts;
    }

    /**
     * Sets the value of the vts property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlVTS }
     *     
     */
    public void setVTS(XmlVTS value) {
        this.vts = value;
    }

    /**
     * Gets the value of the certificateChain property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCertificateChain }
     *     
     */
    public XmlCertificateChain getCertificateChain() {
        return certificateChain;
    }

    /**
     * Sets the value of the certificateChain property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCertificateChain }
     *     
     */
    public void setCertificateChain(XmlCertificateChain value) {
        this.certificateChain = value;
    }

    /**
     * Gets the value of the conclusion property.
     * 
     * @return
     *     possible object is
     *     {@link XmlConclusion }
     *     
     */
    public XmlConclusion getConclusion() {
        return conclusion;
    }

    /**
     * Sets the value of the conclusion property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlConclusion }
     *     
     */
    public void setConclusion(XmlConclusion value) {
        this.conclusion = value;
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
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Context getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(Context value) {
        this.type = value;
    }

}
