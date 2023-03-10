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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

public class POEComparatorTest {
	
	@Test
	public void test() {
		POEComparator comparator = new POEComparator();
		
		Calendar calendar = Calendar.getInstance();

		Date currentTime = calendar.getTime();
		POE currentTimePoe = new POE(currentTime);
		
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setType(TimestampType.CONTENT_TIMESTAMP);
		xmlTimestamp.setProductionTime(currentTime);
		TimestampWrapper firstTimestamp = new TimestampWrapper(xmlTimestamp);
		
		assertFalse(comparator.before(currentTimePoe, new POE(firstTimestamp)));
		assertTrue(comparator.before(new POE(firstTimestamp), currentTimePoe));
		
		XmlTimestamp xmlTimestamp2 = new XmlTimestamp();
		xmlTimestamp2.setType(TimestampType.SIGNATURE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(currentTime);
		TimestampWrapper secondTimestamp = new TimestampWrapper(xmlTimestamp2);
		assertTrue(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		calendar.add(Calendar.SECOND, 1);
		xmlTimestamp.setProductionTime(calendar.getTime());
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertTrue(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		
		xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(xmlTimestamp.getProductionTime());
		
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertFalse(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		assertEquals(0, comparator.compare(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		xmlTimestamp.setTimestampedObjects(new ArrayList<>());
		xmlTimestamp2.setTimestampedObjects(Arrays.asList(new XmlTimestampedObject()));
		
		assertTrue(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertFalse(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		assertNotEquals(0, comparator.compare(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		xmlTimestamp2.setType(TimestampType.VALIDATION_DATA_TIMESTAMP);
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertTrue(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		
	}
	
	@Test
	public void nullPointerTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new POE((Date) null));
		assertEquals("The controlTime must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new POE((TimestampWrapper) null));
		assertEquals("The timestampWrapper must be defined!", exception.getMessage());
	}

}
