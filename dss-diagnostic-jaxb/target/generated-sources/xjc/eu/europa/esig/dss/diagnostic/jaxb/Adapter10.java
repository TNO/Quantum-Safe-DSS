//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:50 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.EndorsementType;

public class Adapter10
    extends XmlAdapter<String, EndorsementType>
{


    public EndorsementType unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.EndorsementTypeParser.parse(value));
    }

    public String marshal(EndorsementType value) {
        return (eu.europa.esig.dss.jaxb.parsers.EndorsementTypeParser.print(value));
    }

}
