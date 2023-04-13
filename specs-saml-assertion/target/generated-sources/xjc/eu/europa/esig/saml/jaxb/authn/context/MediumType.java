//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:27 PM CET 
//


package eu.europa.esig.saml.jaxb.authn.context;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for mediumType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <pre>
 * &lt;simpleType name="mediumType"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}NMTOKEN"&gt;
 *     &lt;enumeration value="memory"/&gt;
 *     &lt;enumeration value="smartcard"/&gt;
 *     &lt;enumeration value="token"/&gt;
 *     &lt;enumeration value="MobileDevice"/&gt;
 *     &lt;enumeration value="MobileAuthCard"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "mediumType")
@XmlEnum
public enum MediumType {

    @XmlEnumValue("memory")
    MEMORY("memory"),
    @XmlEnumValue("smartcard")
    SMARTCARD("smartcard"),
    @XmlEnumValue("token")
    TOKEN("token"),
    @XmlEnumValue("MobileDevice")
    MOBILE_DEVICE("MobileDevice"),
    @XmlEnumValue("MobileAuthCard")
    MOBILE_AUTH_CARD("MobileAuthCard");
    private final String value;

    MediumType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static MediumType fromValue(String v) {
        for (MediumType c: MediumType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
