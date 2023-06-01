package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.pades.signature.suite.PAdESHybridCertificateTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * If you run the PAdES non-visible hybrid cert test from here, it will use PDFBox module for
 * handling pdf files
 */
@Suite
@SelectClasses({PAdESHybridCertificateTest.class})
public class PdfBoxPAdESHybridSignatureSuiteTest {
}
