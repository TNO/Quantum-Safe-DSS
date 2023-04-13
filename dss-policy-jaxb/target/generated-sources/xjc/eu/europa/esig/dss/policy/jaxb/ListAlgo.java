//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:36 PM CET 
//


package eu.europa.esig.dss.policy.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ListAlgo complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ListAlgo"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/policy}LevelConstraint"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Algo" type="{http://dss.esig.europa.eu/validation/policy}Algo" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ListAlgo", propOrder = {
    "algos"
})
@XmlSeeAlso({
    AlgoExpirationDate.class
})
public class ListAlgo
    extends LevelConstraint
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "Algo")
    protected List<Algo> algos;

    /**
     * Gets the value of the algos property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the algos property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAlgos().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Algo }
     * 
     * 
     */
    public List<Algo> getAlgos() {
        if (algos == null) {
            algos = new ArrayList<Algo>();
        }
        return this.algos;
    }

}
