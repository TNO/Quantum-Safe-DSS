//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:34 PM CEST 
//


package eu.europa.esig.validationreport.jaxb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementRefs;
import javax.xml.bind.annotation.XmlType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;


/**
 * <p>Java class for SignersDocumentType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignersDocumentType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;choice&gt;
 *           &lt;sequence&gt;
 *             &lt;element name="DigestAlgAndValue" type="{http://uri.etsi.org/01903/v1.3.2#}DigestAlgAndValueType"/&gt;
 *             &lt;element name="SignersDocumentRepresentation" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *           &lt;/sequence&gt;
 *           &lt;element name="SignersDocumentRepresentation" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType"/&gt;
 *         &lt;/choice&gt;
 *         &lt;element name="SignersDocumentRef" type="{http://uri.etsi.org/19102/v1.2.1#}VOReferenceType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignersDocumentType", propOrder = {
    "content"
})
public class SignersDocumentType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElementRefs({
        @XmlElementRef(name = "DigestAlgAndValue", namespace = "http://uri.etsi.org/19102/v1.2.1#", type = JAXBElement.class),
        @XmlElementRef(name = "SignersDocumentRepresentation", namespace = "http://uri.etsi.org/19102/v1.2.1#", type = JAXBElement.class),
        @XmlElementRef(name = "SignersDocumentRef", namespace = "http://uri.etsi.org/19102/v1.2.1#", type = JAXBElement.class)
    })
    protected List<JAXBElement<?>> content;

    /**
     * Gets the rest of the content model. 
     * 
     * <p>
     * You are getting this "catch-all" property because of the following reason: 
     * The field name "SignersDocumentRepresentation" is used by two different parts of a schema. See: 
     * line 133 of file:/C:/Users/amadoria/Documents/Projects/HAPKIDO/WP4/dss-fork/specs-validation-report/src/main/resources/xsd/1910202xmlSchema.xsd
     * line 131 of file:/C:/Users/amadoria/Documents/Projects/HAPKIDO/WP4/dss-fork/specs-validation-report/src/main/resources/xsd/1910202xmlSchema.xsd
     * <p>
     * To get rid of this property, apply a property customization to one 
     * of both of the following declarations to change their names: 
     * Gets the value of the content property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the content property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getContent().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link JAXBElement }{@code <}{@link VOReferenceType }{@code >}
     * {@link JAXBElement }{@code <}{@link VOReferenceType }{@code >}
     * {@link JAXBElement }{@code <}{@link DigestAlgAndValueType }{@code >}
     * 
     * 
     */
    public List<JAXBElement<?>> getContent() {
        if (content == null) {
            content = new ArrayList<JAXBElement<?>>();
        }
        return this.content;
    }

}