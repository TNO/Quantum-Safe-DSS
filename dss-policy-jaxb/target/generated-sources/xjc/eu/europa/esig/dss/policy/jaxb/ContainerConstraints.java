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
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * ASiC specific constraints
 * 
 * <p>Java class for ContainerConstraints complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ContainerConstraints"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="AcceptableContainerTypes" type="{http://dss.esig.europa.eu/validation/policy}MultiValuesConstraint" minOccurs="0"/&gt;
 *         &lt;element name="ZipCommentPresent" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="AcceptableZipComment" type="{http://dss.esig.europa.eu/validation/policy}MultiValuesConstraint" minOccurs="0"/&gt;
 *         &lt;element name="MimeTypeFilePresent" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="AcceptableMimeTypeFileContent" type="{http://dss.esig.europa.eu/validation/policy}MultiValuesConstraint" minOccurs="0"/&gt;
 *         &lt;element name="ManifestFilePresent" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="SignedFilesPresent" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="AllFilesSigned" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ContainerConstraints", propOrder = {
    "acceptableContainerTypes",
    "zipCommentPresent",
    "acceptableZipComment",
    "mimeTypeFilePresent",
    "acceptableMimeTypeFileContent",
    "manifestFilePresent",
    "signedFilesPresent",
    "allFilesSigned"
})
public class ContainerConstraints
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "AcceptableContainerTypes")
    protected MultiValuesConstraint acceptableContainerTypes;
    @XmlElement(name = "ZipCommentPresent")
    protected LevelConstraint zipCommentPresent;
    @XmlElement(name = "AcceptableZipComment")
    protected MultiValuesConstraint acceptableZipComment;
    @XmlElement(name = "MimeTypeFilePresent")
    protected LevelConstraint mimeTypeFilePresent;
    @XmlElement(name = "AcceptableMimeTypeFileContent")
    protected MultiValuesConstraint acceptableMimeTypeFileContent;
    @XmlElement(name = "ManifestFilePresent")
    protected LevelConstraint manifestFilePresent;
    @XmlElement(name = "SignedFilesPresent")
    protected LevelConstraint signedFilesPresent;
    @XmlElement(name = "AllFilesSigned")
    protected LevelConstraint allFilesSigned;

    /**
     * Gets the value of the acceptableContainerTypes property.
     * 
     * @return
     *     possible object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public MultiValuesConstraint getAcceptableContainerTypes() {
        return acceptableContainerTypes;
    }

    /**
     * Sets the value of the acceptableContainerTypes property.
     * 
     * @param value
     *     allowed object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public void setAcceptableContainerTypes(MultiValuesConstraint value) {
        this.acceptableContainerTypes = value;
    }

    /**
     * Gets the value of the zipCommentPresent property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getZipCommentPresent() {
        return zipCommentPresent;
    }

    /**
     * Sets the value of the zipCommentPresent property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setZipCommentPresent(LevelConstraint value) {
        this.zipCommentPresent = value;
    }

    /**
     * Gets the value of the acceptableZipComment property.
     * 
     * @return
     *     possible object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public MultiValuesConstraint getAcceptableZipComment() {
        return acceptableZipComment;
    }

    /**
     * Sets the value of the acceptableZipComment property.
     * 
     * @param value
     *     allowed object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public void setAcceptableZipComment(MultiValuesConstraint value) {
        this.acceptableZipComment = value;
    }

    /**
     * Gets the value of the mimeTypeFilePresent property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getMimeTypeFilePresent() {
        return mimeTypeFilePresent;
    }

    /**
     * Sets the value of the mimeTypeFilePresent property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setMimeTypeFilePresent(LevelConstraint value) {
        this.mimeTypeFilePresent = value;
    }

    /**
     * Gets the value of the acceptableMimeTypeFileContent property.
     * 
     * @return
     *     possible object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public MultiValuesConstraint getAcceptableMimeTypeFileContent() {
        return acceptableMimeTypeFileContent;
    }

    /**
     * Sets the value of the acceptableMimeTypeFileContent property.
     * 
     * @param value
     *     allowed object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public void setAcceptableMimeTypeFileContent(MultiValuesConstraint value) {
        this.acceptableMimeTypeFileContent = value;
    }

    /**
     * Gets the value of the manifestFilePresent property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getManifestFilePresent() {
        return manifestFilePresent;
    }

    /**
     * Sets the value of the manifestFilePresent property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setManifestFilePresent(LevelConstraint value) {
        this.manifestFilePresent = value;
    }

    /**
     * Gets the value of the signedFilesPresent property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getSignedFilesPresent() {
        return signedFilesPresent;
    }

    /**
     * Sets the value of the signedFilesPresent property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setSignedFilesPresent(LevelConstraint value) {
        this.signedFilesPresent = value;
    }

    /**
     * Gets the value of the allFilesSigned property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getAllFilesSigned() {
        return allFilesSigned;
    }

    /**
     * Sets the value of the allFilesSigned property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setAllFilesSigned(LevelConstraint value) {
        this.allFilesSigned = value;
    }

}
