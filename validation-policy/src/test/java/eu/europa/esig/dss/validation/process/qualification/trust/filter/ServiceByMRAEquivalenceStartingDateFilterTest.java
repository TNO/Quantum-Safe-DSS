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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServiceByMRAEquivalenceStartingDateFilterTest {

    private final static Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
    private final static Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
    private final static Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

    @Test
    public void noTSTest() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);
        assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<>())));
    }

    @Test
    public void testValid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    public void testInvalid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE3);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    public void testSameTime() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE1);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    public void testNoDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(null);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    public void testNoStartingDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();

        assertFalse(filter.isAcceptable(service));
    }

}
