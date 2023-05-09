//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:50 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PolicyConstraints complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PolicyConstraints"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/diagnostic}CertificateExtension"&gt;
 *       &lt;attribute name="requireExplicitPolicy" type="{http://www.w3.org/2001/XMLSchema}int" /&gt;
 *       &lt;attribute name="inhibitPolicyMapping" type="{http://www.w3.org/2001/XMLSchema}int" /&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PolicyConstraints")
public class XmlPolicyConstraints
    extends XmlCertificateExtension
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlAttribute(name = "requireExplicitPolicy")
    protected Integer requireExplicitPolicy;
    @XmlAttribute(name = "inhibitPolicyMapping")
    protected Integer inhibitPolicyMapping;

    /**
     * Gets the value of the requireExplicitPolicy property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getRequireExplicitPolicy() {
        return requireExplicitPolicy;
    }

    /**
     * Sets the value of the requireExplicitPolicy property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setRequireExplicitPolicy(Integer value) {
        this.requireExplicitPolicy = value;
    }

    /**
     * Gets the value of the inhibitPolicyMapping property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getInhibitPolicyMapping() {
        return inhibitPolicyMapping;
    }

    /**
     * Sets the value of the inhibitPolicyMapping property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setInhibitPolicyMapping(Integer value) {
        this.inhibitPolicyMapping = value;
    }

}