package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.pades.signature.visible.suite.*;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * If you run the PAdES visible hybrid cert test from here, it will use OpenPDF module for
 * handling pdf files. Not available for PDFBox for whatever reason.
 */
@Suite
@SelectClasses(value = {PAdESHybridVisibleSignaturesTest.class})
public class ITextPAdESHybridVisibleSignatureSuiteTest {
}
