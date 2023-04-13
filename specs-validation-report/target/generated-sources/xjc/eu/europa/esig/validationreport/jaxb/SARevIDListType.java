//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:20 PM CET 
//


package eu.europa.esig.validationreport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SARevIDListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SARevIDListType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"&gt;
 *       &lt;choice maxOccurs="unbounded" minOccurs="0"&gt;
 *         &lt;element name="CRLID" type="{http://uri.etsi.org/19102/v1.2.1#}SACRLIDType"/&gt;
 *         &lt;element name="OCSPID" type="{http://uri.etsi.org/19102/v1.2.1#}SAOCSPIDType"/&gt;
 *       &lt;/choice&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SARevIDListType", propOrder = {
    "crlidOrOCSPID"
})
public class SARevIDListType
    extends AttributeBaseType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElements({
        @XmlElement(name = "CRLID", type = SACRLIDType.class),
        @XmlElement(name = "OCSPID", type = SAOCSPIDType.class)
    })
    protected List<Serializable> crlidOrOCSPID;

    /**
     * Gets the value of the crlidOrOCSPID property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the crlidOrOCSPID property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCRLIDOrOCSPID().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SACRLIDType }
     * {@link SAOCSPIDType }
     * 
     * 
     */
    public List<Serializable> getCRLIDOrOCSPID() {
        if (crlidOrOCSPID == null) {
            crlidOrOCSPID = new ArrayList<Serializable>();
        }
        return this.crlidOrOCSPID;
    }

}
