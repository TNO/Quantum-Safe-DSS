//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:05 PM CET 
//


package eu.europa.esig.xades.jaxb.xades111;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CommitmentTypeIndicationType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CommitmentTypeIndicationType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="CommitmentTypeId" type="{http://uri.etsi.org/01903/v1.1.1#}ObjectIdentifierType"/&gt;
 *         &lt;choice&gt;
 *           &lt;element name="ObjectReference" type="{http://www.w3.org/2001/XMLSchema}anyURI" maxOccurs="unbounded" minOccurs="0"/&gt;
 *           &lt;element name="AllSignedDataObjects" type="{http://www.w3.org/2001/XMLSchema}anyType"/&gt;
 *         &lt;/choice&gt;
 *         &lt;element name="CommitmentTypeQualifiers" type="{http://uri.etsi.org/01903/v1.1.1#}CommitmentTypeQualifiersListType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CommitmentTypeIndicationType", propOrder = {
    "commitmentTypeId",
    "objectReference",
    "allSignedDataObjects",
    "commitmentTypeQualifiers"
})
public class CommitmentTypeIndicationType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "CommitmentTypeId", required = true)
    protected ObjectIdentifierType commitmentTypeId;
    @XmlElement(name = "ObjectReference")
    @XmlSchemaType(name = "anyURI")
    protected List<String> objectReference;
    @XmlElement(name = "AllSignedDataObjects")
    protected Object allSignedDataObjects;
    @XmlElement(name = "CommitmentTypeQualifiers")
    protected CommitmentTypeQualifiersListType commitmentTypeQualifiers;

    /**
     * Gets the value of the commitmentTypeId property.
     * 
     * @return
     *     possible object is
     *     {@link ObjectIdentifierType }
     *     
     */
    public ObjectIdentifierType getCommitmentTypeId() {
        return commitmentTypeId;
    }

    /**
     * Sets the value of the commitmentTypeId property.
     * 
     * @param value
     *     allowed object is
     *     {@link ObjectIdentifierType }
     *     
     */
    public void setCommitmentTypeId(ObjectIdentifierType value) {
        this.commitmentTypeId = value;
    }

    /**
     * Gets the value of the objectReference property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the objectReference property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getObjectReference().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getObjectReference() {
        if (objectReference == null) {
            objectReference = new ArrayList<String>();
        }
        return this.objectReference;
    }

    /**
     * Gets the value of the allSignedDataObjects property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getAllSignedDataObjects() {
        return allSignedDataObjects;
    }

    /**
     * Sets the value of the allSignedDataObjects property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setAllSignedDataObjects(Object value) {
        this.allSignedDataObjects = value;
    }

    /**
     * Gets the value of the commitmentTypeQualifiers property.
     * 
     * @return
     *     possible object is
     *     {@link CommitmentTypeQualifiersListType }
     *     
     */
    public CommitmentTypeQualifiersListType getCommitmentTypeQualifiers() {
        return commitmentTypeQualifiers;
    }

    /**
     * Sets the value of the commitmentTypeQualifiers property.
     * 
     * @param value
     *     allowed object is
     *     {@link CommitmentTypeQualifiersListType }
     *     
     */
    public void setCommitmentTypeQualifiers(CommitmentTypeQualifiersListType value) {
        this.commitmentTypeQualifiers = value;
    }

}
