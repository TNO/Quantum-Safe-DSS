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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

public class JAdESLevelBDetachedByUriByHashHttpParsTest extends AbstractJAdESMultipleDocumentSignatureTest {

    private static final String DOC_ONE_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURIHash-2.html";
    private static final String DOC_TWO_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURIHash-2.html";

    private JAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns;
    private JAdESService jadesService;

    @BeforeEach
    public void init() throws Exception {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURIHash-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURIHash-2.html");
        documentOne.setName(DOC_TWO_NAME);
        documentToSigns = Arrays.asList(documentOne, documentTwo);

        jadesService = new JAdESService(getOfflineCertificateVerifier());

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return documentToSigns;
    }

    @Override
    protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return jadesService;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

}
