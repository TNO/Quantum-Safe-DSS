//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:21:34 PM CEST 
//


package eu.europa.esig.validationreport.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.validationreport.enums.ObjectType;

public class Adapter3
    extends XmlAdapter<String, ObjectType>
{


    public ObjectType unmarshal(String value) {
        return (eu.europa.esig.validationreport.parsers.UriBasedEnumParser.parseObjectType(value));
    }

    public String marshal(ObjectType value) {
        return (eu.europa.esig.validationreport.parsers.UriBasedEnumParser.print(value));
    }

}
