//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:08 PM CEST 
//


package eu.europa.esig.xades.jaxb.xades111;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

public class Adapter1
    extends XmlAdapter<String, ObjectIdentifierQualifier>
{


    public ObjectIdentifierQualifier unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.ObjectIdentifierQualifierParser.parse(value));
    }

    public String marshal(ObjectIdentifierQualifier value) {
        return (eu.europa.esig.dss.jaxb.parsers.ObjectIdentifierQualifierParser.print(value));
    }

}
