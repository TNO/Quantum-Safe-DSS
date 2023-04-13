//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:43 PM CET 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CertificateExtension complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateExtension"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="octets" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="OID" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="description" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="critical" type="{http://www.w3.org/2001/XMLSchema}boolean" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateExtension", propOrder = {
    "octets"
})
@XmlSeeAlso({
    XmlKeyUsages.class,
    XmlExtendedKeyUsages.class,
    XmlCertificatePolicies.class,
    XmlSubjectAlternativeNames.class,
    XmlBasicConstraints.class,
    XmlPolicyConstraints.class,
    XmlInhibitAnyPolicy.class,
    XmlNameConstraints.class,
    XmlCRLDistributionPoints.class,
    XmlAuthorityInformationAccess.class,
    XmlAuthorityKeyIdentifier.class,
    XmlSubjectKeyIdentifier.class,
    XmlIdPkixOcspNoCheck.class,
    XmlValAssuredShortTermCertificate.class,
    XmlQcStatements.class
})
public class XmlCertificateExtension implements Serializable
{

    private final static long serialVersionUID = 1L;
    protected byte[] octets;
    @XmlAttribute(name = "OID")
    protected String oid;
    @XmlAttribute(name = "description")
    protected String description;
    @XmlAttribute(name = "critical")
    protected Boolean critical;

    /**
     * Gets the value of the octets property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getOctets() {
        return octets;
    }

    /**
     * Sets the value of the octets property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setOctets(byte[] value) {
        this.octets = value;
    }

    /**
     * Gets the value of the oid property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOID() {
        return oid;
    }

    /**
     * Sets the value of the oid property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOID(String value) {
        this.oid = value;
    }

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

    /**
     * Gets the value of the critical property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isCritical() {
        return critical;
    }

    /**
     * Sets the value of the critical property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setCritical(Boolean value) {
        this.critical = value;
    }

}
