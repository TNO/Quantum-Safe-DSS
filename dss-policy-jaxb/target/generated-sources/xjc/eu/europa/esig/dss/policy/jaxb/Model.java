//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:46 PM CEST 
//


package eu.europa.esig.dss.policy.jaxb;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Model.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <pre>
 * &lt;simpleType name="Model"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="SHELL"/&gt;
 *     &lt;enumeration value="CHAIN"/&gt;
 *     &lt;enumeration value="HYBRID"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "Model")
@XmlEnum
public enum Model {

    SHELL,
    CHAIN,
    HYBRID;

    public String value() {
        return name();
    }

    public static Model fromValue(String v) {
        return valueOf(v);
    }

}
