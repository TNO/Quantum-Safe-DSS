//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CertificatePolicy complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificatePolicy"&gt;
 *   &lt;simpleContent&gt;
 *     &lt;extension base="&lt;http://dss.esig.europa.eu/validation/diagnostic&gt;OID"&gt;
 *       &lt;attribute name="cpsUrl" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *     &lt;/extension&gt;
 *   &lt;/simpleContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificatePolicy")
public class XmlCertificatePolicy
    extends XmlOID
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlAttribute(name = "cpsUrl")
    protected String cpsUrl;

    /**
     * Gets the value of the cpsUrl property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCpsUrl() {
        return cpsUrl;
    }

    /**
     * Sets the value of the cpsUrl property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCpsUrl(String value) {
        this.cpsUrl = value;
    }

}
