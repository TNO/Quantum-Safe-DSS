//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.03.13 at 02:23:54 PM CET 
//


package eu.europa.esig.dss.simplereport.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.ASiCContainerType;

public class Adapter2
    extends XmlAdapter<String, ASiCContainerType>
{


    public ASiCContainerType unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.ASiCContainerTypeParser.parse(value));
    }

    public String marshal(ASiCContainerType value) {
        return (eu.europa.esig.dss.jaxb.parsers.ASiCContainerTypeParser.print(value));
    }

}
