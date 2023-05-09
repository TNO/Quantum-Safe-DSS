//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:56 PM CEST 
//


package eu.europa.esig.dss.detailedreport.jaxb;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ConstraintsConclusionWithProofOfExistence complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ConstraintsConclusionWithProofOfExistence"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/detailed-report}ConstraintsConclusion"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="ProofOfExistence" type="{http://dss.esig.europa.eu/validation/detailed-report}ProofOfExistence" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ConstraintsConclusionWithProofOfExistence", propOrder = {
    "proofOfExistence"
})
@XmlSeeAlso({
    XmlValidationProcessBasicSignature.class,
    XmlValidationProcessLongTermData.class,
    XmlValidationProcessArchivalData.class
})
public class XmlConstraintsConclusionWithProofOfExistence
    extends XmlConstraintsConclusion
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "ProofOfExistence")
    protected XmlProofOfExistence proofOfExistence;

    /**
     * Gets the value of the proofOfExistence property.
     * 
     * @return
     *     possible object is
     *     {@link XmlProofOfExistence }
     *     
     */
    public XmlProofOfExistence getProofOfExistence() {
        return proofOfExistence;
    }

    /**
     * Sets the value of the proofOfExistence property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlProofOfExistence }
     *     
     */
    public void setProofOfExistence(XmlProofOfExistence value) {
        this.proofOfExistence = value;
    }

}