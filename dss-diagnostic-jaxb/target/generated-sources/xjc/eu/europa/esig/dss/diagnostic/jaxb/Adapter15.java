//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.TimestampType;

public class Adapter15
    extends XmlAdapter<String, TimestampType>
{


    public TimestampType unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.TimestampTypeParser.parse(value));
    }

    public String marshal(TimestampType value) {
        return (eu.europa.esig.dss.jaxb.parsers.TimestampTypeParser.print(value));
    }

}
