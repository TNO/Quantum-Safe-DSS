//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:59 PM CEST 
//


package eu.europa.esig.dss.simplereport.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.TimestampQualification;

public class Adapter7
    extends XmlAdapter<String, TimestampQualification>
{


    public TimestampQualification unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.TimestampQualificationParser.parse(value));
    }

    public String marshal(TimestampQualification value) {
        return (eu.europa.esig.dss.jaxb.parsers.TimestampQualificationParser.print(value));
    }

}
