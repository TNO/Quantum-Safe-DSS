//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:43 PM CET 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.GeneralNameType;

public class Adapter6
    extends XmlAdapter<String, GeneralNameType>
{


    public GeneralNameType unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.GeneralNameTypeParser.parse(value));
    }

    public String marshal(GeneralNameType value) {
        return (eu.europa.esig.dss.jaxb.parsers.GeneralNameTypeParser.print(value));
    }

}
