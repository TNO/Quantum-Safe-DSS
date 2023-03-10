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
package eu.europa.esig.dss.enumerations;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class MimeTypeTest {

    @Test
    public void fromFileNameTest() {
        assertEquals(MimeTypeEnum.TEXT, MimeType.fromFileName("test.txt"));
        assertEquals(MimeTypeEnum.PDF, MimeType.fromFileName("pades.pdf"));
        assertEquals(MimeTypeEnum.PKCS7, MimeType.fromFileName("cades.p7s"));
        assertEquals(MimeTypeEnum.PKCS7, MimeType.fromFileName("CADES.P7S"));
        assertEquals(MimeTypeEnum.PKCS7, MimeType.fromFileName("cades.p7m"));
        assertEquals(MimeTypeEnum.ASICS, MimeType.fromFileName("container.scs"));
        assertEquals(MimeTypeEnum.ASICS, MimeType.fromFileName("container.asics"));
        assertEquals(MimeTypeEnum.ASICE, MimeType.fromFileName("container.sce"));
        assertEquals(MimeTypeEnum.ASICE, MimeType.fromFileName("container.asice"));
        assertEquals(MimeTypeEnum.ASICE, MimeType.fromFileName("container.bdoc"));
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName("binaries"));
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName("new.folder/binaries"));

        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName(""));
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName(null));
    }

    @Test
    public void getExtensionTest() {
        assertEquals("txt", MimeTypeEnum.TEXT.getExtension());
        assertEquals("pdf", MimeTypeEnum.PDF.getExtension());
        assertEquals("zip", MimeTypeEnum.ZIP.getExtension());

        assertNull(MimeTypeEnum.BINARY.getExtension());
    }

    @Test
    public void getFileExtensionTest() {
        assertEquals("txt", MimeType.getFileExtension("test.txt"));
        assertEquals("pdf", MimeType.getFileExtension("pades.pdf"));
        assertEquals("p7s", MimeType.getFileExtension("cades.p7s"));
        assertEquals("P7S", MimeType.getFileExtension("CADES.P7S"));
        assertEquals("", MimeType.getFileExtension("binaries"));
        assertEquals("folder/binaries", MimeType.getFileExtension("new.folder/binaries"));

        assertNull(MimeType.getFileExtension(""));
        assertNull(MimeType.getFileExtension(null));
    }

    @Test
    public void fromMimeTypeStringTest() {
        assertEquals(MimeTypeEnum.XML, MimeType.fromMimeTypeString("text/xml"));
        assertEquals(MimeTypeEnum.PDF, MimeType.fromMimeTypeString("application/pdf"));
        assertEquals(MimeTypeEnum.PNG, MimeType.fromMimeTypeString("image/png"));
        assertEquals(MimeTypeEnum.ASICE, MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip"));

        MimeType asiceNewLineMimeType = MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip\n");
        assertNotNull(asiceNewLineMimeType);
        assertNotEquals(MimeTypeEnum.ASICE, asiceNewLineMimeType);
    }

}
