/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

class GrantedTrustServiceTest {

    @Test
    void test() throws Exception {
        TSPServiceType tspService = new TSPServiceType();
        TSPServiceInformationType informationType = new TSPServiceInformationType();
        GrantedTrustService selector = new GrantedTrustService();

        tspService.setServiceInformation(informationType);
        
        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
        
        assertTrue(selector.test(tspService));
        
        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");        
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation");
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited");
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked");
        assertFalse(selector.test(tspService));
        
        assertFalse(selector.test(null));
        
        informationType.setServiceStatus(null);
        assertFalse(selector.test(tspService));
        
        assertFalse(selector.test(null));
        
        ServiceHistoryType serviceHistory = new ServiceHistoryType();
        tspService.setServiceHistory(serviceHistory);
        
        ServiceHistoryInstanceType historyInstance = new ServiceHistoryInstanceType();
        historyInstance.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked");
        serviceHistory.getServiceHistoryInstance().add(historyInstance);
        assertFalse(selector.test(tspService));

        historyInstance.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
        tspService.getServiceHistory().getServiceHistoryInstance().add(historyInstance);
        assertTrue(selector.test(tspService));
    }

}