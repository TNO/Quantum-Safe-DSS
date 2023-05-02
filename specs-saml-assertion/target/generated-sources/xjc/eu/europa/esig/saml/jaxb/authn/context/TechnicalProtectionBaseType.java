//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:40 PM CEST 
//


package eu.europa.esig.saml.jaxb.authn.context;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TechnicalProtectionBaseType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TechnicalProtectionBaseType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;choice minOccurs="0"&gt;
 *           &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}PrivateKeyProtection"/&gt;
 *           &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}SecretKeyProtection"/&gt;
 *         &lt;/choice&gt;
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}Extension" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TechnicalProtectionBaseType", propOrder = {
    "privateKeyProtection",
    "secretKeyProtection",
    "extension"
})
public class TechnicalProtectionBaseType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "PrivateKeyProtection")
    protected PrivateKeyProtectionType privateKeyProtection;
    @XmlElement(name = "SecretKeyProtection")
    protected SecretKeyProtectionType secretKeyProtection;
    @XmlElement(name = "Extension")
    protected List<ExtensionType> extension;

    /**
     * Gets the value of the privateKeyProtection property.
     * 
     * @return
     *     possible object is
     *     {@link PrivateKeyProtectionType }
     *     
     */
    public PrivateKeyProtectionType getPrivateKeyProtection() {
        return privateKeyProtection;
    }

    /**
     * Sets the value of the privateKeyProtection property.
     * 
     * @param value
     *     allowed object is
     *     {@link PrivateKeyProtectionType }
     *     
     */
    public void setPrivateKeyProtection(PrivateKeyProtectionType value) {
        this.privateKeyProtection = value;
    }

    /**
     * Gets the value of the secretKeyProtection property.
     * 
     * @return
     *     possible object is
     *     {@link SecretKeyProtectionType }
     *     
     */
    public SecretKeyProtectionType getSecretKeyProtection() {
        return secretKeyProtection;
    }

    /**
     * Sets the value of the secretKeyProtection property.
     * 
     * @param value
     *     allowed object is
     *     {@link SecretKeyProtectionType }
     *     
     */
    public void setSecretKeyProtection(SecretKeyProtectionType value) {
        this.secretKeyProtection = value;
    }

    /**
     * Gets the value of the extension property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the extension property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getExtension().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ExtensionType }
     * 
     * 
     */
    public List<ExtensionType> getExtension() {
        if (extension == null) {
            extension = new ArrayList<ExtensionType>();
        }
        return this.extension;
    }

}
