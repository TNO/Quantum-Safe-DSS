//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:46 PM CEST 
//


package eu.europa.esig.dss.policy.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * Integer value check : follows the specified level behavior when the checked element is compliant with the defined constraint value
 * 
 * <p>Java class for IntValueConstraint complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IntValueConstraint"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/policy}LevelConstraint"&gt;
 *       &lt;attribute name="value" type="{http://www.w3.org/2001/XMLSchema}int" /&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IntValueConstraint")
public class IntValueConstraint
    extends LevelConstraint
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlAttribute(name = "value")
    protected Integer value;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setValue(Integer value) {
        this.value = value;
    }

}
