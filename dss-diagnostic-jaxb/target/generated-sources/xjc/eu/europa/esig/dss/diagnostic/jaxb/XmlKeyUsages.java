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
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import eu.europa.esig.dss.enumerations.KeyUsageBit;


/**
 * <p>Java class for KeyUsages complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KeyUsages"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/diagnostic}CertificateExtension"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="keyUsageBit" type="{http://dss.esig.europa.eu/validation/diagnostic}KeyUsageBit" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyUsages", propOrder = {
    "keyUsageBit"
})
public class XmlKeyUsages
    extends XmlCertificateExtension
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(type = String.class)
    @XmlJavaTypeAdapter(Adapter19 .class)
    protected List<KeyUsageBit> keyUsageBit;

    /**
     * Gets the value of the keyUsageBit property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the keyUsageBit property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getKeyUsageBit().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<KeyUsageBit> getKeyUsageBit() {
        if (keyUsageBit == null) {
            keyUsageBit = new ArrayList<KeyUsageBit>();
        }
        return this.keyUsageBit;
    }

}
