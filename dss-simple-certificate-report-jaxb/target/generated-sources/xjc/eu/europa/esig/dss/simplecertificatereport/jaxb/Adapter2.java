//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 04:22:02 PM CEST 
//


package eu.europa.esig.dss.simplecertificatereport.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.KeyUsageBit;

public class Adapter2
    extends XmlAdapter<String, KeyUsageBit>
{


    public KeyUsageBit unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.KeyUsageBitParser.parse(value));
    }

    public String marshal(KeyUsageBit value) {
        return (eu.europa.esig.dss.jaxb.parsers.KeyUsageBitParser.print(value));
    }

}
