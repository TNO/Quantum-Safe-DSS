//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:35 PM CEST 
//


package eu.europa.esig.dss.simplecertificatereport.jaxb;

import java.util.Date;
import javax.xml.bind.annotation.adapters.XmlAdapter;

public class Adapter1
    extends XmlAdapter<String, Date>
{


    public Date unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.DateParser.parse(value));
    }

    public String marshal(Date value) {
        return (eu.europa.esig.dss.jaxb.parsers.DateParser.print(value));
    }

}
