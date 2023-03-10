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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class XAdESExtensionCToATest extends AbstractXAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_C;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_A;
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        if (SignatureLevel.XAdES_C.equals(diagnosticData.getFirstSignatureFormat())) {
            super.verifySourcesAndDiagnosticDataWithOrphans(advancedSignatures, diagnosticData);

        } else if (SignatureLevel.XAdES_A.equals(diagnosticData.getFirstSignatureFormat())) {
            super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

        } else {
            fail("Unexpected format " + diagnosticData.getFirstSignatureFormat());
        }
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_A, diagnosticData.getFirstSignatureFormat());
    }

}
