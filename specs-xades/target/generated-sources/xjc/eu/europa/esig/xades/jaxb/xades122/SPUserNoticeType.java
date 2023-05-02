//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:22 PM CEST 
//


package eu.europa.esig.xades.jaxb.xades122;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SPUserNoticeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SPUserNoticeType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="NoticeRef" type="{http://uri.etsi.org/01903/v1.2.2#}NoticeReferenceType" minOccurs="0"/&gt;
 *         &lt;element name="ExplicitText" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SPUserNoticeType", propOrder = {
    "noticeRef",
    "explicitText"
})
public class SPUserNoticeType
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "NoticeRef")
    protected NoticeReferenceType noticeRef;
    @XmlElement(name = "ExplicitText")
    protected String explicitText;

    /**
     * Gets the value of the noticeRef property.
     * 
     * @return
     *     possible object is
     *     {@link NoticeReferenceType }
     *     
     */
    public NoticeReferenceType getNoticeRef() {
        return noticeRef;
    }

    /**
     * Sets the value of the noticeRef property.
     * 
     * @param value
     *     allowed object is
     *     {@link NoticeReferenceType }
     *     
     */
    public void setNoticeRef(NoticeReferenceType value) {
        this.noticeRef = value;
    }

    /**
     * Gets the value of the explicitText property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getExplicitText() {
        return explicitText;
    }

    /**
     * Sets the value of the explicitText property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setExplicitText(String value) {
        this.explicitText = value;
    }

}
