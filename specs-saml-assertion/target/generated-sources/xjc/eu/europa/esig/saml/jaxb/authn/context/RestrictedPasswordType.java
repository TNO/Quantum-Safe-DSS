//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:40 PM CEST 
//


package eu.europa.esig.saml.jaxb.authn.context;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RestrictedPasswordType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RestrictedPasswordType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{urn:oasis:names:tc:SAML:2.0:ac}PasswordType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Length" type="{urn:oasis:names:tc:SAML:2.0:ac}RestrictedLengthType"/&gt;
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}Generation" minOccurs="0"/&gt;
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}Extension" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="ExternalVerification" type="{http://www.w3.org/2001/XMLSchema}anyURI" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RestrictedPasswordType")
public class RestrictedPasswordType
    extends PasswordType
    implements Serializable
{

    private final static long serialVersionUID = 1L;

}