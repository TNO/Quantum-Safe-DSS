//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:40 PM CEST 
//


package eu.europa.esig.saml.jaxb.assertion;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DecisionType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <pre>
 * &lt;simpleType name="DecisionType"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="Permit"/&gt;
 *     &lt;enumeration value="Deny"/&gt;
 *     &lt;enumeration value="Indeterminate"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "DecisionType")
@XmlEnum
public enum DecisionType {

    @XmlEnumValue("Permit")
    PERMIT("Permit"),
    @XmlEnumValue("Deny")
    DENY("Deny"),
    @XmlEnumValue("Indeterminate")
    INDETERMINATE("Indeterminate");
    private final String value;

    DecisionType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DecisionType fromValue(String v) {
        for (DecisionType c: DecisionType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}