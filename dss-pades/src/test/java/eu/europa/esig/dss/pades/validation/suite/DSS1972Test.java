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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1972Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1959/pades-revoc-removed-from-dss-dict.pdf"));
	}
	
	@Override
	protected CertificateSource getTrustedCertificateSource() {
		CertificateSource certificateSource = new CommonTrustedCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEtzCCA5+gAwIBAgIKFg5NNQAAAAADhzANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJMVDErMCkGA1UEChMiU2thaXRtZW5pbmlvIHNlcnRpZmlrYXZpbW8gY2VudHJhczEgMB4GA1UECxMXQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxITAfBgNVBAMTGFNTQyBRdWFsaWZpZWQgQ2xhc3MgMyBDQTAeFw0xMjA1MTUxMTM0NTRaFw0yMjA1MTUxMTM0NTRaMFUxCzAJBgNVBAYTAkxUMRAwDgYDVQQHEwdWaWxuaXVzMRYwFAYDVQQKEw1CYWxUc3RhbXAgVUFCMRwwGgYDVQQDExNCYWxUc3RhbXAgUVRTQSBUU1UyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAghxPoFLFWpkLa2Ll1ZBUtesItzJMa2wpBIBwqTHdWMkOM9kv3tSK05xpfCMKhU7Xt9kwPzqDXpIg5PTuDWLXjWdbjkp14rfvUTybR/IfOOe8zSQozIjoEW3EIzDiRksgUYxo2FCIHqLrRu3lKziWryEoOX8H6vGie18a6VUVV+8Qqm8sVuXCZaS0Q6RwOI11vZgn609iFKtSLQFZVPP0Mluq/csPfzlAelesHwwtRsTLpWjtGluZe1kNBky+JP1sVcHbbYuHTklCXGGn2jCZbxg/TY8vAnnSuIdf8ufx5HtOSdzW3ciGqn3MzwTUgGdNZSDtcZDoeeG2SgRsVZ2qDQIDAQABo4IBXTCCAVkwHQYDVR0OBBYEFFH0sW1OVQ7fk5dcgyNlE3B99q8/MB8GA1UdIwQYMBaAFAjJQf/nm1Yz2vDXs2G0SFwVoxtaMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9uY3JsLnNzYy5sdC9jbGFzczNucWMvY2FjcmwuY3JsMGwGCCsGAQUFBwEBBGAwXjA2BggrBgEFBQcwAoYqaHR0cDovL3d3dy5zc2MubHQvY2FjZXJ0L3NzY19jbGFzczNucWMuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC0zbnFjLnNzYy5sdC8wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwPQYDVR0gBDYwNDAyBgsrBgEEAYGvZQECADAjMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNzYy5sdC9jcHMwDQYJKoZIhvcNAQEFBQADggEBADq7F9uq7ROIFr2V3q+eqVVdD2qTZ437wJKziaYho059h1Vqg5CMoY6Diu6JsosEkYoIsV39LaH+PU/anvysMiD0taViWR+p5O1ZTUXjyk7Cj16tgLeXGosQlJEQexS0WIyMTC4F/9Zv0U95HwALnarJLh2KvWsGRcDXsHmK3BVybs87/CAgVuN10d50xCcSFtdFhqe9pyZsaqZnnNKXc9eRuf8QrpJGTI38UldA+v2k5A0tBnrJOFXvutxGFdSV+5WofGYGWf7HUYXJ71mbrCd7udOvWSLUa4mAyElJ/YoEs3fZU/00eBduUJyLwBLAA7oA0R8n4gdV3JynrhghG9o="));
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFvTCCA6WgAwIBAgIQWJFmnMAIyiVAcLMn/5wGnjANBgkqhkiG9w0BAQUFADB0MQswCQYDVQQGEwJMVDErMCkGA1UEChMiU2thaXRtZW5pbmlvIHNlcnRpZmlrYXZpbW8gY2VudHJhczEgMB4GA1UECxMXQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDVNTQyBSb290IENBIEEwHhcNMTIwMzAzMTEwMDE3WhcNMjYxMDI1MTIwNTAwWjB/MQswCQYDVQQGEwJMVDErMCkGA1UEChMiU2thaXRtZW5pbmlvIHNlcnRpZmlrYXZpbW8gY2VudHJhczEgMB4GA1UECxMXQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxITAfBgNVBAMTGFNTQyBRdWFsaWZpZWQgQ2xhc3MgMyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ31J4TmT6WT7ezYrZTD3bUD5YpucJRophhaVGFeMVP0h5UwV9uYs3Ne+eFubk5eY+dgBcvK142CudGExMjbFap8il/Ik8PFsLW5DKLscoblIKuAR42u9TgYRv9mmfXZQEwsUUlC3ajCsbqkVV2zdl84kpJX2L2pKy94j28GJ4ezSiOHj/G2ZfTUAu38k/sIlH/Mg4m9KJYwthzg/2pJ4gzWSGtqOGX8/FNOAT3n7M3dtlZZStaIPO4icySMpGRF6mH5kz9peSdSr/1ywYnPQk0y1nZjUeeaGnaM7Ik8ez2G8h3kgRVuUZyLLEJtTZwMN5HwKpNIPTysw+YRxrgG59MCAwEAAaOCAT4wggE6MGQGCCsGAQUFBwEBBFgwVjAzBggrBgEFBQcwAoYnaHR0cDovL3d3dy5zc2MubHQvY2FjZXJ0L3NzY19yb290X2EuY3J0MB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcDIuc3NjLmx0MB8GA1UdIwQYMBaAFMy/3qeQd2JqHXhpLgo4m3dRUwPwMAwGA1UdEwQFMAMBAf8wPQYDVR0gBDYwNDAyBgsrBgEEAYGvZQECADAjMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNzYy5sdC9jcHMwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL3d3dy5zc2MubHQvY3JsL3NzY19yb290X2EuY3JsMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUCMlB/+ebVjPa8NezYbRIXBWjG1owDQYJKoZIhvcNAQEFBQADggIBAFwDXedviP9lST/mIhdxwUkiMB/7rXfwnXfIFVur8/wmzevqJyTU96OmYw2jkDQmzCAdI/8yj8QKekp0Y8xyslJu6X1MNhgmUmYjaA3Dt5QPVFr5I8Y9vTGUeSmGrXhSfWCcfN0DpWV96h1PHpbLXdAh1cl4LikoasVrWxDsQZuQ7FxCkXMmTYzxQzy1AHU+3zq5NmgBb3WdwqKhRx9JHpb8xhSCqK3K/RGsiVEBYnyVhTYuK5it5MHgFSA66gPDd3YYzdVp5KZsxBWkidnPxGKLskmAyfAxjrmHdsrKnZwK6L+SiLGgTzedvKK+AVxxcG8WtekFMc4zUWXe87U2l3NydgHkCaw1vSBXNZHAxEhN/645oo2oNkMyBlEbvUw12lQYLa5jLlfEfRPvB1qhCTfvP9xbSvgf6yABrLNE5x33wAr8eTIu378IuIiiUzzfDAflDT+QGH2j9J8XAyscVSyAVgc5MdGJsdSQTuY3MzdzRRGm9+ahaWXSCOt+BL2UXRDU1cHYlJdgz1kR7Ozfdkf4Cb3nwxxzYH/zhtUGsdbApuglj01pquN8k4ELoJWGkJXVL90+Ulk+SjfvBnxCpRysfngbpgAPxSVwAXQzz2sQCOHLMQ86HuB40hERBxePozfciEzRW5DrVYpPu/ami20pVMLzkFo4ARLXVdeK5ugp"));
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIHyDCCBbCgAwIBAgIQc89Alm7KoeNYmE4j9Ko7fTANBgkqhkiG9w0BAQsFADA4MQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xEzARBgNVBAMMCkl6ZW5wZS5jb20wHhcNMTcwMjA2MTAyMTIzWhcNMjIwMjA2MTAyMTIzWjBWMQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xGDAWBgNVBGEMD1ZBVEVTLUEwMTMzNzI2MDEXMBUGA1UEAwwOdHNhLml6ZW5wZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCl2p1wLCY3z0ylWNQfbJjATWB9IyyegVATH0pMANrjd3LBvH9aJVocgBmZ0yaAM4Ur29s3hAiK/hwB2KUKmZufhuLwK89PSi1Vq/T3k7pzaRWMAcqsNbI3D+L4HIoE2fMuBmRurs5U+6hakTQkzw4P+1NDiXY0Lv4h7IZhQfS7osr1R+7YNF5Fl0BW/aMChOsxa0pgtceTyjfc6UAkEtkNY6Tl/Wt1m8ahyeBDqKld7BBC/DOpL/5q22sn0JXjyrXBlVUdSx9IBblI7miLqxyDqEAirER6Kp7IRVMM8t+sKKILUcT6k4VySKkTmHpO93tws26lllgz5BMdNg81Sq2DCQSpl3igsbvzANgYhX79QTJRxkYsiDAMlheI/87IGqBF/RUdT6DCmubl7q4G+ZVNPKWFV5R/bKEyV0mX5sDfJ9zzS7ZXmRfAgnp7q6GIT5GHB30UXnadic0WywTmF2VAsHGgUi5/TiWpJZG2KohGFWfM6xhnC7Rl9vn1GceIYgfAGHyF2V0IrhfICO4viZRYQ2tq5sBxjvAOhE6h2F5Wa2O/V1M7fV52MVhGHgUjw7Gl87UYByKUABXCsAMzLYa/4BtVFeLNdZkJbGuZVEMG5cdem7IYuFc25SwZzcDSb9LeDYQaXq2rA7YMpmg8yR/+0jvIpvdRzapMXDtW8pnnlQIDAQABo4ICrjCCAqowgbAGA1UdEgSBqDCBpYEPaW5mb0BpemVucGUuY29tpIGRMIGOMUcwRQYDVQQKDD5JWkVOUEUgUy5BLiAtIENJRiBBMDEzMzcyNjAtUk1lcmMuVml0b3JpYS1HYXN0ZWl6IFQxMDU1IEY2MiBTODFDMEEGA1UECQw6QXZkYSBkZWwgTWVkaXRlcnJhbmVvIEV0b3JiaWRlYSAxNCAtIDAxMDEwIFZpdG9yaWEtR2FzdGVpejAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFOfHaTOpL9BhMn53Iz0GnwyFgeF2MB8GA1UdIwQYMBaAFB0cZQ6o8iV7tJHP5LGx5r1VdGwFMDcGCCsGAQUFBwELBCswKTAnBggrBgEFBQcwA4YbaHR0cDovL3RzYS5pemVucGUuY29tOjgwOTMvMIIBHQYDVR0gBIIBFDCCARAwggEMBgkrBgEEAfM5AwMwgf4wJQYIKwYBBQUHAgEWGWh0dHA6Ly93d3cuaXplbnBlLmNvbS9jcHMwgdQGCCsGAQUFBwICMIHHGoHEQmVybWVlbiBtdWdhayBlemFndXR6ZWtvIHd3dy5pemVucGUuY29tIFppdXJ0YWdpcmlhbiBrb25maWFudHphIGl6YW4gYXVycmV0aWsga29udHJhdHVhIGlyYWt1cnJpLkxpbWl0YWNpb25lcyBkZSBnYXJhbnRpYXMgZW4gd3d3Lml6ZW5wZS5jb20gQ29uc3VsdGUgZWwgY29udHJhdG8gYW50ZXMgZGUgY29uZmlhciBlbiBlbCBjZXJ0aWZpY2FkbzAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLml6ZW5wZS5jb20vY2dpLWJpbi9hcmwyMA0GCSqGSIb3DQEBCwUAA4ICAQBqJcHprXlHOCBJwWuEABCj16SA7zQLvNnB/5azLMp6fxfutBf6xhNHTozZBQsqpa8E0UB+x0Catdtcrsi3TsQAidD/icTNm0yR7mR8fM4WyUwdMLPRRRJyIOJnWffKqpmjdknmQkusSX/c9u4b1txm1pS34nXtCfJEBcrtPubTqzGQq5mw7kuU+rE+gYLFSX+rCAqG8+SdA0Ccgv2KxvEWeFunzehUkrcNqhEDkYVfNhRD39df+k+3vrmybr1ubZ76Rl2NHmq4tn0Peqa3+17+ggoQ2L1YWWZw/vqTXxiZI47SUcK47BTKUQjO16SGu3s3hKW9g3AIEpEoayRUj9zeQPO9er3Ku8iJ9Rp+39WmjwO5CmiPA3L2mFd+vbrea1gKWsdwtv6p7gBfmlq1EJeHMWck91SQxSfNOFSPpsPY/bfUQ9LLiq+AoJeYDELJbpOjcsJr4iGGbOFytkUNKE7hT6ZMkFBI01lLyB1XIs7UvUtTnOKhoCjq922VEv99kT9BjecHDbDCrba37yj3xOXZyTZ8dCCkOlhjOX2vjQ4vvt31HSa46eVMds+6bLUDnGn9KC6aTp+2hcv37tM/gtXjE//VNuFHl4F18pea3qg7vGkWCHLPMYE7fy4LhJZdFCGt9QCChn5ogt6f2mF3diKbAD8IOhpRQKI6GJpCyq6RRg=="));
		return certificateSource;
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		assertEquals(2, diagnosticData.getAllRevocationData().size());

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> revocationData = signature.foundRevocations().getRelatedRevocationData();
		assertEquals(1, revocationData.size());

		String revocationId = revocationData.iterator().next().getId();
		
		int firstDssDictTimestampCounter = 0;
		int secondDssDictTimestampCounter = 0;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				List<RevocationWrapper> allTimestampedRevocations = timestampWrapper.getTimestampedRevocations();
				if (allTimestampedRevocations.size() == 1) {
					assertFalse(timestampWrapper.getTimestampedRevocations().stream().
							map(RevocationWrapper::getId).collect(Collectors.toList()).contains(revocationId));
					++firstDssDictTimestampCounter;
				} else if (allTimestampedRevocations.size() == 2) {
					assertTrue(timestampWrapper.getTimestampedRevocations().stream().
							map(RevocationWrapper::getId).collect(Collectors.toList()).contains(revocationId));
					++secondDssDictTimestampCounter;
				}
			}
		}
		assertEquals(1, firstDssDictTimestampCounter);
		assertEquals(2, secondDssDictTimestampCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertCertificateChainWithinFoundCertificates(signatureWrapper.getCertificateChain(), signatureWrapper.foundCertificates());
		}
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			assertCertificateChainWithinFoundCertificates(timestampWrapper.getCertificateChain(), timestampWrapper.foundCertificates());
		}
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertCertificateChainWithinFoundCertificates(revocationWrapper.getCertificateChain(), revocationWrapper.foundCertificates());
		}
	}

	private void assertCertificateChainWithinFoundCertificates(List<CertificateWrapper> certChain, FoundCertificatesProxy foundCertificates) {
		Set<String> certIds = foundCertificates.getRelatedCertificates().stream().map(c -> c.getId()).collect(Collectors.toSet());
		for (CertificateWrapper certificateWrapper : certChain) {
			if (certificateWrapper.isTrusted()) {
				break;
			}
			assertTrue(certIds.contains(certificateWrapper.getId()));
		}
	}

}
