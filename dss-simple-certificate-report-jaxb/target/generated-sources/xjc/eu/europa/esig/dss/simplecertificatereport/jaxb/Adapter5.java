//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:22:02 PM CEST 
//


package eu.europa.esig.dss.simplecertificatereport.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.Indication;

public class Adapter5
    extends XmlAdapter<String, Indication>
{


    public Indication unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.IndicationParser.parse(value));
    }

    public String marshal(Indication value) {
        return (eu.europa.esig.dss.jaxb.parsers.IndicationParser.print(value));
    }

}
