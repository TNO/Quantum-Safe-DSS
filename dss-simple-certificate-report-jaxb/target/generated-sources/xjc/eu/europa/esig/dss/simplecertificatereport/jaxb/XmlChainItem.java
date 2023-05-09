//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:22:02 PM CEST 
//


package eu.europa.esig.dss.simplecertificatereport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SubIndication;


/**
 * <p>Java class for ChainItem complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ChainItem"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="id" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="subject" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Subject"/&gt;
 *         &lt;element name="issuerId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="notBefore" type="{http://www.w3.org/2001/XMLSchema}dateTime"/&gt;
 *         &lt;element name="notAfter" type="{http://www.w3.org/2001/XMLSchema}dateTime"/&gt;
 *         &lt;element name="keyUsages" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}KeyUsages" minOccurs="0"/&gt;
 *         &lt;element name="extendedKeyUsages" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}ExtendedKeyUsages" minOccurs="0"/&gt;
 *         &lt;element name="ocspUrls" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="ocspUrl" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="crlUrls" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="crlUrl" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="aiaUrls" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="aiaUrl" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="cpsUrls" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="cpsUrl" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="pdsUrls" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="pdsUrl" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="qualificationAtIssuance" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}CertificateQualification" minOccurs="0"/&gt;
 *         &lt;element name="qualificationDetailsAtIssuance" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Details" minOccurs="0"/&gt;
 *         &lt;element name="qualificationAtValidation" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}CertificateQualification" minOccurs="0"/&gt;
 *         &lt;element name="qualificationDetailsAtValidation" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Details" minOccurs="0"/&gt;
 *         &lt;element name="enactedMRA" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/&gt;
 *         &lt;element name="revocation" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Revocation" minOccurs="0"/&gt;
 *         &lt;element name="trustAnchors" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}TrustAnchors" minOccurs="0"/&gt;
 *         &lt;element name="Indication" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Indication"/&gt;
 *         &lt;element name="SubIndication" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}SubIndication" minOccurs="0"/&gt;
 *         &lt;element name="X509ValidationDetails" type="{http://dss.esig.europa.eu/validation/simple-certificate-report}Details" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ChainItem", propOrder = {
    "id",
    "subject",
    "issuerId",
    "notBefore",
    "notAfter",
    "keyUsages",
    "extendedKeyUsages",
    "ocspUrls",
    "crlUrls",
    "aiaUrls",
    "cpsUrls",
    "pdsUrls",
    "qualificationAtIssuance",
    "qualificationDetailsAtIssuance",
    "qualificationAtValidation",
    "qualificationDetailsAtValidation",
    "enactedMRA",
    "revocation",
    "trustAnchors",
    "indication",
    "subIndication",
    "x509ValidationDetails"
})
public class XmlChainItem implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(required = true)
    protected String id;
    @XmlElement(required = true)
    protected XmlSubject subject;
    protected String issuerId;
    @XmlElement(required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date notBefore;
    @XmlElement(required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date notAfter;
    @XmlElementWrapper
    @XmlElement(name = "keyUsage", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report", type = String.class)
    @XmlJavaTypeAdapter(Adapter2 .class)
    protected List<KeyUsageBit> keyUsages = new ArrayList<KeyUsageBit>();
    @XmlElementWrapper
    @XmlElement(name = "extendedKeyUsage", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> extendedKeyUsages = new ArrayList<String>();
    @XmlElementWrapper
    @XmlElement(name = "ocspUrl", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> ocspUrls = new ArrayList<String>();
    @XmlElementWrapper
    @XmlElement(name = "crlUrl", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> crlUrls = new ArrayList<String>();
    @XmlElementWrapper
    @XmlElement(name = "aiaUrl", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> aiaUrls = new ArrayList<String>();
    @XmlElementWrapper
    @XmlElement(name = "cpsUrl", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> cpsUrls = new ArrayList<String>();
    @XmlElementWrapper
    @XmlElement(name = "pdsUrl", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<String> pdsUrls = new ArrayList<String>();
    @XmlElement(type = String.class)
    @XmlJavaTypeAdapter(Adapter4 .class)
    protected CertificateQualification qualificationAtIssuance;
    protected XmlDetails qualificationDetailsAtIssuance;
    @XmlElement(type = String.class)
    @XmlJavaTypeAdapter(Adapter4 .class)
    protected CertificateQualification qualificationAtValidation;
    protected XmlDetails qualificationDetailsAtValidation;
    protected Boolean enactedMRA;
    protected XmlRevocation revocation;
    @XmlElementWrapper
    @XmlElement(name = "trustAnchor", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
    protected List<XmlTrustAnchor> trustAnchors = new ArrayList<XmlTrustAnchor>();
    @XmlElement(name = "Indication", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter5 .class)
    protected Indication indication;
    @XmlElement(name = "SubIndication", type = String.class)
    @XmlJavaTypeAdapter(Adapter6 .class)
    protected SubIndication subIndication;
    @XmlElement(name = "X509ValidationDetails")
    protected XmlDetails x509ValidationDetails;

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
     * Gets the value of the subject property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSubject }
     *     
     */
    public XmlSubject getSubject() {
        return subject;
    }

    /**
     * Sets the value of the subject property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSubject }
     *     
     */
    public void setSubject(XmlSubject value) {
        this.subject = value;
    }

    /**
     * Gets the value of the issuerId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIssuerId() {
        return issuerId;
    }

    /**
     * Sets the value of the issuerId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIssuerId(String value) {
        this.issuerId = value;
    }

    /**
     * Gets the value of the notBefore property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * Sets the value of the notBefore property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNotBefore(Date value) {
        this.notBefore = value;
    }

    /**
     * Gets the value of the notAfter property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * Sets the value of the notAfter property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNotAfter(Date value) {
        this.notAfter = value;
    }

    /**
     * Gets the value of the qualificationAtIssuance property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public CertificateQualification getQualificationAtIssuance() {
        return qualificationAtIssuance;
    }

    /**
     * Sets the value of the qualificationAtIssuance property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setQualificationAtIssuance(CertificateQualification value) {
        this.qualificationAtIssuance = value;
    }

    /**
     * Gets the value of the qualificationDetailsAtIssuance property.
     * 
     * @return
     *     possible object is
     *     {@link XmlDetails }
     *     
     */
    public XmlDetails getQualificationDetailsAtIssuance() {
        return qualificationDetailsAtIssuance;
    }

    /**
     * Sets the value of the qualificationDetailsAtIssuance property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlDetails }
     *     
     */
    public void setQualificationDetailsAtIssuance(XmlDetails value) {
        this.qualificationDetailsAtIssuance = value;
    }

    /**
     * Gets the value of the qualificationAtValidation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public CertificateQualification getQualificationAtValidation() {
        return qualificationAtValidation;
    }

    /**
     * Sets the value of the qualificationAtValidation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setQualificationAtValidation(CertificateQualification value) {
        this.qualificationAtValidation = value;
    }

    /**
     * Gets the value of the qualificationDetailsAtValidation property.
     * 
     * @return
     *     possible object is
     *     {@link XmlDetails }
     *     
     */
    public XmlDetails getQualificationDetailsAtValidation() {
        return qualificationDetailsAtValidation;
    }

    /**
     * Sets the value of the qualificationDetailsAtValidation property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlDetails }
     *     
     */
    public void setQualificationDetailsAtValidation(XmlDetails value) {
        this.qualificationDetailsAtValidation = value;
    }

    /**
     * Gets the value of the enactedMRA property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isEnactedMRA() {
        return enactedMRA;
    }

    /**
     * Sets the value of the enactedMRA property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setEnactedMRA(Boolean value) {
        this.enactedMRA = value;
    }

    /**
     * Gets the value of the revocation property.
     * 
     * @return
     *     possible object is
     *     {@link XmlRevocation }
     *     
     */
    public XmlRevocation getRevocation() {
        return revocation;
    }

    /**
     * Sets the value of the revocation property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlRevocation }
     *     
     */
    public void setRevocation(XmlRevocation value) {
        this.revocation = value;
    }

    /**
     * Gets the value of the indication property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Indication getIndication() {
        return indication;
    }

    /**
     * Sets the value of the indication property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIndication(Indication value) {
        this.indication = value;
    }

    /**
     * Gets the value of the subIndication property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public SubIndication getSubIndication() {
        return subIndication;
    }

    /**
     * Sets the value of the subIndication property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSubIndication(SubIndication value) {
        this.subIndication = value;
    }

    /**
     * Gets the value of the x509ValidationDetails property.
     * 
     * @return
     *     possible object is
     *     {@link XmlDetails }
     *     
     */
    public XmlDetails getX509ValidationDetails() {
        return x509ValidationDetails;
    }

    /**
     * Sets the value of the x509ValidationDetails property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlDetails }
     *     
     */
    public void setX509ValidationDetails(XmlDetails value) {
        this.x509ValidationDetails = value;
    }

    public List<KeyUsageBit> getKeyUsages() {
        return keyUsages;
    }

    public void setKeyUsages(List<KeyUsageBit> keyUsages) {
        this.keyUsages = keyUsages;
    }

    public List<String> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }

    public void setExtendedKeyUsages(List<String> extendedKeyUsages) {
        this.extendedKeyUsages = extendedKeyUsages;
    }

    public List<String> getOcspUrls() {
        return ocspUrls;
    }

    public void setOcspUrls(List<String> ocspUrls) {
        this.ocspUrls = ocspUrls;
    }

    public List<String> getCrlUrls() {
        return crlUrls;
    }

    public void setCrlUrls(List<String> crlUrls) {
        this.crlUrls = crlUrls;
    }

    public List<String> getAiaUrls() {
        return aiaUrls;
    }

    public void setAiaUrls(List<String> aiaUrls) {
        this.aiaUrls = aiaUrls;
    }

    public List<String> getCpsUrls() {
        return cpsUrls;
    }

    public void setCpsUrls(List<String> cpsUrls) {
        this.cpsUrls = cpsUrls;
    }

    public List<String> getPdsUrls() {
        return pdsUrls;
    }

    public void setPdsUrls(List<String> pdsUrls) {
        this.pdsUrls = pdsUrls;
    }

    public List<XmlTrustAnchor> getTrustAnchors() {
        return trustAnchors;
    }

    public void setTrustAnchors(List<XmlTrustAnchor> trustAnchors) {
        this.trustAnchors = trustAnchors;
    }

}