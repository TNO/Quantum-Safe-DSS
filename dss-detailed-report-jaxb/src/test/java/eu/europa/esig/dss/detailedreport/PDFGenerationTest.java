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
package eu.europa.esig.dss.detailedreport;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryBuilder;
import org.apache.fop.apps.MimeConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.xml.transform.Result;
import javax.xml.transform.sax.SAXResult;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PDFGenerationTest {

	private static FopFactory fopFactory;
	private static FOUserAgent foUserAgent;

	@BeforeAll
	public static void init() throws Exception {
		FopFactoryBuilder builder = new FopFactoryBuilder(new File(".").toURI());
		builder.setAccessibility(true);

		fopFactory = builder.build();

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS");
		foUserAgent.setAccessibility(true);
	}

	@Test
	public void generateDetailedReport() throws Exception {
		createAndValidate("dr1.xml");
	}

	@Test
	public void generateDetailedReport2() throws Exception {
		createAndValidate("dr2.xml");
	}

	@Test
	public void generateTstDetailedReport() throws Exception {
		createAndValidate("dr-tst.xml");
	}

	@Test
	public void generateCertificateDetailedReport() throws Exception {
		createAndValidate("dr-cert.xml");
	}

	@Test
	public void generateSigAndTstDetailedReport() throws Exception {
		createAndValidate("dr-sig-and-tst.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/" + filename);
		XmlDetailedReport detailedReport = facade.unmarshall(file);
		String detailedReportString = facade.marshall(detailedReport);

		try (FileOutputStream fos = new FileOutputStream("target/report.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
		
		File pdfReport = new File("target/report.pdf");
		assertTrue(pdfReport.exists());
		assertTrue(pdfReport.delete(), "Cannot delete PDF document (IO error)");
		assertFalse(pdfReport.exists());

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, baos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReportString, result);
			assertTrue(baos.toByteArray().length >= 0);
		}
		
	}

}
