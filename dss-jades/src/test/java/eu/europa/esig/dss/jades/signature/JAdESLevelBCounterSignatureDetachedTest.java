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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESLevelBCounterSignatureDetachedTest extends AbstractJAdESCounterSignatureTest {

    private JAdESService service;
    private DSSDocument documentToSign;

    private Date signingDate;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signingDate = new Date();
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
        JAdESCounterSignatureParameters signatureParameters = new JAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        return signatureParameters;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(new InMemoryDocument(byteArray));
        assertTrue(jwsJsonSerializationParser.isSupported());

        JWSJsonSerializationObject jsonSerializationObject = jwsJsonSerializationParser.parse();
        List<JWS> jwsSignatures = jsonSerializationObject.getSignatures();
        assertEquals(1, jwsSignatures.size());

        JWS jws = jwsSignatures.iterator().next();
        List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
        assertEquals(1, etsiU.size());

        Map<String, Object> item = DSSJsonUtils.parseEtsiUComponent(etsiU.iterator().next());
        assertEquals(1, item.size());

        String cSig = (String) item.get(JAdESHeaderParameterNames.C_SIG);
        assertNotNull(cSig);

        JWSCompactSerializationParser compactSerializationParser = new JWSCompactSerializationParser(new InMemoryDocument(cSig.getBytes()));
        assertTrue(compactSerializationParser.isSupported());

        JWS counterJWS = compactSerializationParser.parse();
        assertNotNull(counterJWS);
        assertNotNull(counterJWS.getEncodedHeader());
        assertNotNull(counterJWS.getSignatureValue());
        assertTrue(Utils.isArrayEmpty(counterJWS.getUnverifiedPayloadBytes()));

        try {
            String jsonString = new String(DSSJsonUtils.fromBase64Url(counterJWS.getEncodedHeader()));
            Map<String, Object> protectedHeaderMap = JsonUtil.parseJson(jsonString);

            Object cty = protectedHeaderMap.get(HeaderParameterNames.CONTENT_TYPE);
            assertNull(cty);
        } catch (JoseException e) {
            fail(e);
        }
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        boolean counterSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
                assertEquals(1, signatureScopes.size());

                XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
                assertEquals(SignatureScopeType.COUNTER_SIGNATURE, xmlSignatureScope.getScope());
                assertEquals(signatureWrapper.getParent().getId(), xmlSignatureScope.getName());

                counterSignatureFound = true;
            }
        }
        assertTrue(counterSignatureFound);
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
