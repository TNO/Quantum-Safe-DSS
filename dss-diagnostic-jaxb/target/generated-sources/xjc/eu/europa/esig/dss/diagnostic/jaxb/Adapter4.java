//
// This file was generated by the Eclipse Implementation of JAXB, v2.3.7 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 02:43:27 PM CEST 
//


package eu.europa.esig.dss.diagnostic.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import eu.europa.esig.dss.enumerations.CertificationPermission;

public class Adapter4
    extends XmlAdapter<String, CertificationPermission>
{


    public CertificationPermission unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.CertificationPermissionParser.parse(value));
    }

    public String marshal(CertificationPermission value) {
        return (eu.europa.esig.dss.jaxb.parsers.CertificationPermissionParser.print(value));
    }

}
