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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESOverwrittenDSSDictTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-HU_POL-7.pdf"));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIGcDCCBVigAwIBAgIOAUbLtXUbdHvJbqLvlgowDQYJKoZIhvcNAQELBQAwgYIxCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UECgwNTWljcm9zZWMgTHRkLjEnMCUGA1UEAwweUXVhbGlmaWVkIGUtU3ppZ25vIFFDUCBDQSAyMDEyMR8wHQYJKoZIhvcNAQkBFhBpbmZvQGUtc3ppZ25vLmh1MB4XDTE5MDkyNjEzMDAwMFoXDTIyMTIzMDIxNTk1OVowgYAxCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UECgwNTWljcm9zZWMgTHRkLjEXMBUGA1UEYQwOVkFUSFUtMjM1ODQ0OTcxLTArBgNVBAMMJFF1YWxpZmllZCBlSURBUyBlLVN6aWdubyBUU0EgMjAxOSAwMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJaa/Zq1iGSy141D9uNOPu7DoqKkzGG6UP9iYUccs8pHpMFWI5D0jKmJf97pzWLj365/dXcrNkNmx2n8urOregM3jnT7RhgCLZpaT0g+9G/xMGwUJicIxf5We+kO10EWqbVJ+NILx8/gO3VvyibxXxhHL+4Q++CmDN2mufeRUgu0V7xRTvFeNs9AmXmOM23lhgDxpTUwnJ1J6Go/ucaw+NLoT4vB1DcxWLLn6HF0yw9SCFVjcFY/UVhG4jfEf+CNKs/SmiB2vMIjkApnqgDDWbacojzyfFX6qcOIoLvgjtV7J5ft6f0qUBVw9hDDwcJWdh8NDnddktrWGIpAgMsSQ1sCAwEAAaOCAuIwggLeMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCB9gYDVR0gBIHuMIHrMIHoBg8rBgEEAYGoGAIBAYE2AgswgdQwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcC5lLXN6aWduby5odS9xY3BzMFQGCCsGAQUFBwICMEgMRkxpbWl0YXRpb24gb2YgZmluYW5jaWFsIGxpYWJpbGl0eTogMTAwLDAwMCBIVUYgcGVyIGluc3VyYW5jZSBpbmNpZGVudC4wVAYIKwYBBQUHAgIwSAxGUMOpbnrDvGd5aSBmZWxlbMWRc3PDqWcga29ybMOhdG96w6FzYTogMTAwIDAwMCBGdCBrw6FyZXNlbcOpbnllbmvDqW50LjAdBgNVHQ4EFgQUoQodghe4I8Zj3PalNgS7iDs4pocwHwYDVR0jBBgwFoAUzD1G6GUAu+rDvc+3iOGV/1N5o7QwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5lLXN6aWduby5odS9xY3BjYTIwMTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAqBggrBgEFBQcwAYYeaHR0cDovL3FjcG9jc3AyMDEyLmUtc3ppZ25vLmh1MDAGCCsGAQUFBzAChiRodHRwOi8vd3d3LmUtc3ppZ25vLmh1L3FjcGNhMjAxMi5jcnQwKwYDVR0QBCQwIoAPMjAxOTA5MjYxMzAwMDBagQ8yMDIwMTIyNjEzMDAwMFowgagGCCsGAQUFBwEDBIGbMIGYMAgGBgQAjkYBATAVBgYEAI5GAQIwCxMDSFVGAgEBAgEFMAsGBgQAjkYBAwIBCjBTBgYEAI5GAQUwSTAkFh5odHRwczovL2NwLmUtc3ppZ25vLmh1L3FjcHNfZW4TAmVuMCEWG2h0dHBzOi8vY3AuZS1zemlnbm8uaHUvcWNwcxMCaHUwEwYGBACORgEGMAkGBwQAjkYBBgIwDQYJKoZIhvcNAQELBQADggEBAHBLrw25ba7My8TESno7yQHZe7kC7JqtFPsCyCesBmVMslYo9Y4es+kYzlduYIygQ45xPvYwRRwXuVfOQ0FKE6vEhebcu56YSwU4YYr15/hdp0ddQjWFWD/zNW6RkT6WAGFmFfclkKXka+CDpJZsQUFUpMbGkAQWu+CXW189TvqFAoovrCRsZ8Ic8AjREvGgNZZWgqaLGjPhn1C0Gcph3oB0FgF2vAw4Z3lPFcv+hn1YVYNg223Ols/2g3xENXx9eI+UNzRoMbQXzwYlfW4T2kKd8c/BtCjZ9ELjZVHkvvNsG6HXQUxgdb2rBotGL06GFOLelnEOYFAr1CKiyEpFcoI="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEpzCCBEygAwIBAgINAJ4sXrlZ/XdM3YZqCjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xFzAVBgNVBGEMDlZBVEhVLTIzNTg0NDk3MR4wHAYDVQQDDBVlLVN6aWdubyBSb290IENBIDIwMTcwHhcNMTcwOTE3MjEwMDAwWhcNNDIwODIyMDkwMDAwWjB6MQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xFzAVBgNVBGEMDlZBVEhVLTIzNTg0NDk3MScwJQYDVQQDDB5lLVN6aWdubyBRdWFsaWZpZWQgUUNQIENBIDIwMTcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASkLCREhsR4UUgppCQtg+HjcUjwsdK/j8s46Lq+vV80F5gmTxklJWLGA1ctRNFFSXpL+TWseaI7HJ6iRCnUz0qzo4ICvjCCArowDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwOwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcC5lLXN6aWduby5odS9hY3BzMB0GA1UdDgQWBBQH9izCA0NfdmcXt6SBh5rMRTB93jAfBgNVHSMEGDAWgBSHERUI0arBeAyxr87GyZDvvzAEwDCBtgYDVR0fBIGuMIGrMDegNaAzhjFodHRwOi8vcm9vdGNhMjAxNy1jcmwxLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMTcuY3JsMDegNaAzhjFodHRwOi8vcm9vdGNhMjAxNy1jcmwyLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMTcuY3JsMDegNaAzhjFodHRwOi8vcm9vdGNhMjAxNy1jcmwzLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMTcuY3JsMIIBXwYIKwYBBQUHAQEEggFRMIIBTTAvBggrBgEFBQcwAYYjaHR0cDovL3Jvb3RjYTIwMTctb2NzcDEuZS1zemlnbm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA6Ly9yb290Y2EyMDE3LW9jc3AyLmUtc3ppZ25vLmh1MC8GCCsGAQUFBzABhiNodHRwOi8vcm9vdGNhMjAxNy1vY3NwMy5lLXN6aWduby5odTA8BggrBgEFBQcwAoYwaHR0cDovL3Jvb3RjYTIwMTctY2ExLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMTcuY3J0MDwGCCsGAQUFBzAChjBodHRwOi8vcm9vdGNhMjAxNy1jYTIuZS1zemlnbm8uaHUvcm9vdGNhMjAxNy5jcnQwPAYIKwYBBQUHMAKGMGh0dHA6Ly9yb290Y2EyMDE3LWNhMy5lLXN6aWduby5odS9yb290Y2EyMDE3LmNydDAKBggqhkjOPQQDAgNJADBGAiEA3U9F2Hi0oY7uCbLoUv6RA9pQCiqEfz75ad2K33FAeKsCIQDF/7RMDBvY9IsXvPYJR9Bm/4wGFRE+cNElXL55j/uXnw=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEsTCCBFegAwIBAgINAKmJWM/YAa8Abx5pCjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xFzAVBgNVBGEMDlZBVEhVLTIzNTg0NDk3MR4wHAYDVQQDDBVlLVN6aWdubyBSb290IENBIDIwMTcwHhcNMTcwOTE3MjEwMDAwWhcNNDIwODIyMDkwMDAwWjBwMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xFzAVBgNVBGEMDlZBVEhVLTIzNTg0NDk3MR0wGwYDVQQDDBRlLVN6aWdubyBUU0EgQ0EgMjAxNzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMl33K45f5BqanH6+ZvrwBPvMWwEir11QCUiLpO71hsJjXJOKbgwS0xAhUJUox0L9ECYfI1j2At5wzsDibIg4rajggLTMIICzzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDCDA7BgNVHSAENDAyMDAGBFUdIAAwKDAmBggrBgEFBQcCARYaaHR0cDovL2NwLmUtc3ppZ25vLmh1L2FjcHMwHQYDVR0OBBYEFP+jH35x+pff+PmFRDR48+fSlm1jMB8GA1UdIwQYMBaAFIcRFQjRqsF4DLGvzsbJkO+/MATAMIG2BgNVHR8Ega4wgaswN6A1oDOGMWh0dHA6Ly9yb290Y2EyMDE3LWNybDEuZS1zemlnbm8uaHUvcm9vdGNhMjAxNy5jcmwwN6A1oDOGMWh0dHA6Ly9yb290Y2EyMDE3LWNybDIuZS1zemlnbm8uaHUvcm9vdGNhMjAxNy5jcmwwN6A1oDOGMWh0dHA6Ly9yb290Y2EyMDE3LWNybDMuZS1zemlnbm8uaHUvcm9vdGNhMjAxNy5jcmwwggFfBggrBgEFBQcBAQSCAVEwggFNMC8GCCsGAQUFBzABhiNodHRwOi8vcm9vdGNhMjAxNy1vY3NwMS5lLXN6aWduby5odTAvBggrBgEFBQcwAYYjaHR0cDovL3Jvb3RjYTIwMTctb2NzcDIuZS1zemlnbm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA6Ly9yb290Y2EyMDE3LW9jc3AzLmUtc3ppZ25vLmh1MDwGCCsGAQUFBzAChjBodHRwOi8vcm9vdGNhMjAxNy1jYTEuZS1zemlnbm8uaHUvcm9vdGNhMjAxNy5jcnQwPAYIKwYBBQUHMAKGMGh0dHA6Ly9yb290Y2EyMDE3LWNhMi5lLXN6aWduby5odS9yb290Y2EyMDE3LmNydDA8BggrBgEFBQcwAoYwaHR0cDovL3Jvb3RjYTIwMTctY2EzLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMTcuY3J0MAoGCCqGSM49BAMCA0gAMEUCIQCrk9SCpF7GLnC5zHdcyD4lTnMBzr2J2gVLQ5WNau1T1AIgGQRaoXoxAC04l898oEd18kewn/4dyOZohc1JeSYXQko="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIHKjCCBtGgAwIBAgIOAUbM8jzohmzPVFOP2AowCgYIKoZIzj0EAwIwcDELMAkGA1UEBhMCSFUxETAPBgNVBAcMCEJ1ZGFwZXN0MRYwFAYDVQQKDA1NaWNyb3NlYyBMdGQuMRcwFQYDVQRhDA5WQVRIVS0yMzU4NDQ5NzEdMBsGA1UEAwwUZS1Temlnbm8gVFNBIENBIDIwMTcwHhcNMTkwOTI2MTMwMDAwWhcNMzEwOTI2MTMwMDAwWjB6MQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xFzAVBgNVBGEMDlZBVEhVLTIzNTg0NDk3MScwJQYDVQQDDB5lLVN6aWdubyBRdWFsaWZpZWQgVFNBIDIwMTkgMDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATDOg1aJ60/t1T9u58yih49StsQMRBRWv0SBiaoeUuEgMso4oizG3dm13seQ9IClef1sAR+fou62uOG6xOj53yxo4IFQzCCBT8wDgYDVR0PAQH/BAQDAgbAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIH2BgNVHSAEge4wgeswgegGDysGAQQBgagYAgEBgTYCCzCB1DAmBggrBgEFBQcCARYaaHR0cDovL2NwLmUtc3ppZ25vLmh1L3FjcHMwVAYIKwYBBQUHAgIwSAxGTGltaXRhdGlvbiBvZiBmaW5hbmNpYWwgbGlhYmlsaXR5OiAxMDAsMDAwIEhVRiBwZXIgaW5zdXJhbmNlIGluY2lkZW50LjBUBggrBgEFBQcCAjBIDEZQw6luesO8Z3lpIGZlbGVsxZFzc8OpZyBrb3Jsw6F0b3rDoXNhOiAxMDAgMDAwIEZ0IGvDoXJlc2Vtw6lueWVua8OpbnQuMB0GA1UdDgQWBBRrC2XKxVhBGwxEd8QcsA+jDuWc8zAfBgNVHSMEGDAWgBT/ox9+cfqX3/j5hUQ0ePPn0pZtYzCBtgYDVR0fBIGuMIGrMDegNaAzhjFodHRwOi8vZXRzYWNhMjAxNy1jcmwxLmUtc3ppZ25vLmh1L2V0c2FjYTIwMTcuY3JsMDegNaAzhjFodHRwOi8vZXRzYWNhMjAxNy1jcmwyLmUtc3ppZ25vLmh1L2V0c2FjYTIwMTcuY3JsMDegNaAzhjFodHRwOi8vZXRzYWNhMjAxNy1jcmwzLmUtc3ppZ25vLmh1L2V0c2FjYTIwMTcuY3JsMIICSQYIKwYBBQUHAQEEggI7MIICNzAvBggrBgEFBQcwAYYjaHR0cDovL2V0c2FjYTIwMTctb2NzcDEuZS1zemlnbm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA6Ly9ldHNhY2EyMDE3LW9jc3AyLmUtc3ppZ25vLmh1MC8GCCsGAQUFBzABhiNodHRwOi8vZXRzYWNhMjAxNy1vY3NwMy5lLXN6aWduby5odTA8BggrBgEFBQcwAoYwaHR0cDovL2V0c2FjYTIwMTctY2ExLmUtc3ppZ25vLmh1L2V0c2FjYTIwMTcuY3J0MEwGCCsGAQUFBzAChkBodHRwOi8vZXRzYWNhMjAxNy1jYTEuZS1zemlnbm8uaHUvZXRzYWNhMjAxNy1saW5rLXJvb3RjYTIwMDkuY3J0MDwGCCsGAQUFBzAChjBodHRwOi8vZXRzYWNhMjAxNy1jYTIuZS1zemlnbm8uaHUvZXRzYWNhMjAxNy5jcnQwTAYIKwYBBQUHMAKGQGh0dHA6Ly9ldHNhY2EyMDE3LWNhMi5lLXN6aWduby5odS9ldHNhY2EyMDE3LWxpbmstcm9vdGNhMjAwOS5jcnQwPAYIKwYBBQUHMAKGMGh0dHA6Ly9ldHNhY2EyMDE3LWNhMy5lLXN6aWduby5odS9ldHNhY2EyMDE3LmNydDBMBggrBgEFBQcwAoZAaHR0cDovL2V0c2FjYTIwMTctY2EzLmUtc3ppZ25vLmh1L2V0c2FjYTIwMTctbGluay1yb290Y2EyMDA5LmNydDArBgNVHRAEJDAigA8yMDE5MDkyNjEzMDAwMFqBDzIwMjAxMjI2MTMwMDAwWjCBqAYIKwYBBQUHAQMEgZswgZgwCAYGBACORgEBMBUGBgQAjkYBAjALEwNIVUYCAQECAQUwCwYGBACORgEDAgEKMFMGBgQAjkYBBTBJMCQWHmh0dHBzOi8vY3AuZS1zemlnbm8uaHUvcWNwc19lbhMCZW4wIRYbaHR0cHM6Ly9jcC5lLXN6aWduby5odS9xY3BzEwJodTATBgYEAI5GAQYwCQYHBACORgEGAjAKBggqhkjOPQQDAgNHADBEAiAwerGX0HBviRsE5ZowklqaoM0g64UWwzbi1/9TafNZoAIgBXXidg91Xd6EN2XKvmjbonIOUl43asDTb2Q8ZyWR55A="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIE9TCCA92gAwIBAgIMLuujs6+RGksxvbEKMA0GCSqGSIb3DQEBCwUAMIGCMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHk1pY3Jvc2VjIGUtU3ppZ25vIFJvb3QgQ0EgMjAwOTEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5odTAeFw0xMjAzMzAxMjAwMDBaFw0yOTEyMjkxMjAwMDBaMIGCMQswCQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHlF1YWxpZmllZCBlLVN6aWdubyBRQ1AgQ0EgMjAxMjEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5odTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANdZaWRow9po+j0mA658maAb6LaU8VYvjXOAxkph0zBNehDWmMjtKufqYULB8NBZ0cwrAW3T/ImzudYIsneP5xV4Ma0frUcdmJn8el4DFgu9/8SN30WKpXvFJH1tYvas/hMtXvc67P/c6ehe3u8Uhot2v7qT3isGoemXuS3I8E/Z3uEKvvc80zkLHcOjChM8gndJ1M3a4x8d0HbjEN8HBxys8NgOzFf1DGWGlMZgO4duuoHwFeLBz96WthepVZXqJm0hza38FYYlKLPNTwrXK8NYprSfYwGgxJOkoyUQ9EIgWe0O84DafrTCo54B5pY/HW45HrdjWgrI8h6s9MdytqsCAwEAAaOCAWcwggFjMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMDsGA1UdIAQ0MDIwMAYEVR0gADAoMCYGCCsGAQUFBwIBFhpodHRwOi8vY3AuZS1zemlnbm8uaHUvcWNwczAdBgNVHQ4EFgQUzD1G6GUAu+rDvc+3iOGV/1N5o7QwHwYDVR0jBBgwFoAUyw/G30JDzD3LtUgjoRp6piq7NGgwGwYDVR0RBBQwEoEQaW5mb0BlLXN6aWduby5odTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmUtc3ppZ25vLmh1L3Jvb3RjYTIwMDkuY3JsMG4GCCsGAQUFBwEBBGIwYDArBggrBgEFBQcwAYYfaHR0cDovL3Jvb3RvY3NwMjAwOS5lLXN6aWduby5odTAxBggrBgEFBQcwAoYlaHR0cDovL3d3dy5lLXN6aWduby5odS9yb290Y2EyMDA5LmNydDANBgkqhkiG9w0BAQsFAAOCAQEAgaJ7B9CTqKP0UwqUYz0ALi29Xu4n0ls5qhu2/bvmb90/7WLwNLxAPQLkINtaB4HCdhv1WVavZnJznhNaajseJtZ6J4x3GInhBBxspyAQmUdC2nLu0NGMuIS5KbyXo7CdiLyiY+plt1seqVfMlDs9WtXEqg5kvu2DCbwEQ9v0vr5a5SCgqHikQ/uEMyUSAKCYzsd7F8nMaay4r6O5D6Tnzq18i4Hb5jfy3JVYMfzPJxc5ZQrQ4M5t/fb6IJLWhLESze3o47Vag3WjOPXQe97kGOLTQh86hjGbSqj8C0/2isTORVL/vQWXGAGEbZckkjtKwJpSurhpozWCucCQwK7FFg=="));

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.addTrustedCertSources(trustedCertificateSource);

        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatureWrapper.getSignatureFormat());
        }
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        int signatureWithVriCounter = 0;
        int signatureWithoutVriCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            boolean containsVri = false;
            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<OrphanCertificateWrapper> orphanCertificates = foundCertificates.getOrphanCertificates();
            for (OrphanCertificateWrapper certificateWrapper : orphanCertificates) {
                assertTrue(certificateWrapper.getOrigins().contains(CertificateOrigin.DSS_DICTIONARY));
                if (certificateWrapper.getOrigins().contains(CertificateOrigin.VRI_DICTIONARY)) {
                    containsVri = true;
                }
            }
            if (containsVri) {
                ++signatureWithVriCounter;
            } else {
                ++signatureWithoutVriCounter;
            }
        }
        assertEquals(1, signatureWithVriCounter);
        assertEquals(1, signatureWithoutVriCounter);
    }

    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(3, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanCertificateReferences()));
        assertEquals(5, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        boolean emptySigDocFound = false;
        boolean signPdfFound = false;
        for (AdvancedSignature signature : signatures) {
            List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signature.getId());
            if (originalDocuments.size() == 0) {
                emptySigDocFound = true;
            } else {
                signPdfFound = true;
            }
        }
        assertTrue(emptySigDocFound);
        assertTrue(signPdfFound);
    }

}
