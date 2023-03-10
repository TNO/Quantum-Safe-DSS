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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class MultiThreadsTokenIssuerSelectorTest {

    private static CertificateToken certificateToken1;
    private static CertificateToken certificateToken2;
    private static CertificateToken certificateToken3;
    private static CertificateToken certificateToken4;

    private static CertificateToken rootCa;
    private static CertificateToken externalCa;
    private static CertificateToken externalCaAlternative;

    @BeforeAll
    public static void init() {
        certificateToken1 = DSSUtils.loadCertificateFromBase64EncodedString("MIID/TCCAuWgAwIBAgILBAAAAAABFWqxqn4wDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0wNzEwMDQxMjAwMDBaFw0xNDAxMjYyMzAwMDBaMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnNCHpL/dQ+Lv3SGpz/tshgtLZf5qfuYSiPf1Y3gjMYyHBYtB0LWLbZuL6f1/MaFgl2V3rUiAMyoU0Cfrwo1onrH4cr3YBBnDqdQcxdTlZ8inwxdb7ZBvIzr2h1GvaeUv/May9T7jQ4eM8iW1+yMU96THjQeilBxJli0XcKIidpg0okhP97XARg2buEscAMEZe+YBitdHmLcVWv+ZmQhX/gv4debKa9vzZ+qDEbRiMWdopWfrD8VrvJh3+/Da5oi2Cxx/Vgd7ACkOCCVWsfVN2O6T5uq/lZGLmPZCyPVivq1I/CJG6EUDSbaQfA4jzDtBSZ5wUtOobh+VVI6aUaEdQIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTBDBgNVHSAEPDA6MDgGBWA4CQEBMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlIDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NybC9yb290LmNybDARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEBAH1t5NWhYEwrNe6NfOyI0orfIiEoy13BB5w214IoqfGSTivFMZBI2FQeBOquBXkoB253FXQq+mmZMlIl5qn0qprUQKQlicA2cSm0UgBe7SlIQkkxFusl1AgVdjk6oeNkHqxZs+J1SLy0NofzDA+F8BWy4AVSPujQ6x1GK70FdGmea/h9anxodOyPLAvWEckPFxavtvTuxwAjBTfdGB6Z6DvQBq0LtljcrLyojA9uwVDSvcwOTZK5lcTV54aE6KZWX2DapbDi2KY/oL6HfhOiDh+OPqa3YXzvCesY/h5v0RerHFFk49+ItSJryzwRcvYuzk1zYQL5ZykZc/PkVRV3HWE=");
        certificateToken2 = DSSUtils.loadCertificateFromBase64EncodedString("MIID7jCCAtagAwIBAgILBAAAAAABQaHhNLowDQYJKoZIhvcNAQEFBQAwOzEYMBYGA1UEChMPQ3liZXJ0cnVzdCwgSW5jMR8wHQYDVQQDExZDeWJlcnRydXN0IEdsb2JhbCBSb290MB4XDTEzMTAxMDExMDAwMFoXDTI1MDUxMjIyNTkwMFowKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGc0Iekv91D4u/dIanP+2yGC0tl/mp+5hKI9/VjeCMxjIcFi0HQtYttm4vp/X8xoWCXZXetSIAzKhTQJ+vCjWiesfhyvdgEGcOp1BzF1OVnyKfDF1vtkG8jOvaHUa9p5S/8xrL1PuNDh4zyJbX7IxT3pMeNB6KUHEmWLRdwoiJ2mDSiSE/3tcBGDZu4SxwAwRl75gGK10eYtxVa/5mZCFf+C/h15spr2/Nn6oMRtGIxZ2ilZ+sPxWu8mHf78NrmiLYLHH9WB3sAKQ4IJVax9U3Y7pPm6r+VkYuY9kLI9WK+rUj8IkboRQNJtpB8DiPMO0FJnnBS06huH5VUjppRoR1AgMBAAGjggEEMIIBADAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATBQBgNVHSAESTBHMEUGCisGAQQBsT4BZAEwNzA1BggrBgEFBQcCARYpaHR0cDovL2N5YmVydHJ1c3Qub21uaXJvb3QuY29tL3JlcG9zaXRvcnkwHQYDVR0OBBYEFIWK6/TFu74OWQOU3taAARXjEJw5MDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwub21uaXJvb3QuY29tL2N0Z2xvYmFsLmNybDARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUtgh7DXrMrCBMhlYyXs+rboUtcFcwDQYJKoZIhvcNAQEFBQADggEBALLLOUcpFHXrT8gK9htqXI8dV3LlSAooOqLkn+yRRxt/zS9Y0X0opocf56Kjdu+c2dgw6Ph3xE/ytMT5cu/60jT17BTk2MFkQhoAJbM/KIGmvu4ISDGdeobiBtSeiyzRb9JR6JSuuM3LvQp1n0fhsA5HlibT5rFrKi7Oi1luDbc4eAp09nPhAdcgUkRU9o/aAJLAJho3Zu9uSbw5yHW3PRGnmfSO67mwsnSDVswudPrZEkCnSHq/jwOBXAWCYVu5bru3rCdojd5qCTn/WyqbZdsgLAPR5Vmf/uG3d5HxTO1LLX1Zyp9iANuG32+nFusi89shA1GPDKWacEm0ASd8iaU=");
        certificateToken3 = DSSUtils.loadCertificateFromBase64EncodedString("MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");
        certificateToken4 = DSSUtils.loadCertificateFromBase64EncodedString("MIIFwzCCA6ugAwIBAgIUCn6m30tEntpqJIWe5rgV0xZ/u7EwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCTFUxFjAUBgNVBAoMDUx1eFRydXN0IFMuQS4xHzAdBgNVBAMMFkx1eFRydXN0IEdsb2JhbCBSb290IDIwHhcNMTUwMzA1MTMyMTU3WhcNMzUwMzA1MTMyMTU3WjBGMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEfMB0GA1UEAwwWTHV4VHJ1c3QgR2xvYmFsIFJvb3QgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANeFl78RmOnwYoNMPIf5U2o3C/IPPIfOb9wmKb3FibrJgz337spbxm1Jc7TJRqMbNBM/wYlFV/TZsfs2ZUv7COJIcRHIbjuend+JZTemhfY7RBi2xjcwYkSSl2l9QjAk5A0MiWtj3sXh306pFGxT4GHO9hcvHTy95iJMHZP1EMShduxq3sVs35a0VkBCwGKSMKEtFZSg0iAGCW5qbeXrt77U8PEVfIvmTroTzEsnXpk8F12PgX8zPU/TPxvsXD/wPEx1bvKm1Z3aLQdjAsZy6ZS8TEmVT4hSyNvoaYL4zDRbIvCGp4m9SAptZoFtyMhk+wHh9OHe2Z7d21vUKpkmFRseTJIpgp7VkoGSQXAZ96Tlk0u8d2cx3Rz9MXANF5kM+Qw5GSoXtTBxVdUPrljhPS80m8+f9niFwpN6cj5mj5wWEWCPnolvZ77gR1o7DJpni89Gxq44o/KnvObWhWszJHAiS8sIm7vI+AIpHb4gDEa/a4ebsypmQjVGbKq6rfmYe+lQVRQxv7HaLe2ArWgk+2mr2HETMOZns4dA/Yl+8kPREd8vZS9kzl8UubG/Mb2HeFpZZYiq/FkySIbWTLkpS5XTdvN3JW1CHDiDTf2jX5t/Lax5Gw5CMZdjpPuKadUiDTSQMC6otOBttpSsvItO13D8xTiOZCXhTTmQzsmHhFhxAgMBAAGjgagwgaUwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGByuBKwEBAQowLDAqBggrBgEFBQcCARYeaHR0cHM6Ly9yZXBvc2l0b3J5Lmx1eHRydXN0Lmx1MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBT/GCh2+UgFLKGu8SsbK7JT+Et8szAdBgNVHQ4EFgQU/xgodvlIBSyhrvErGyuyU/hLfLMwDQYJKoZIhvcNAQELBQADggIBAGoZFO1uecEsh9QNcH7X9njJCwROxLHOk3D+sFTAMs2ZMGQXvw/l4jP9BzZAcg4atmpZ1gDlaCDdLnINH2pkMSCEfUmmWjfrRcmF9dTHF5kH5ptV5AzoqbTOjFu1EVzPig4N1qx3gf4ynCSecs5U89BvolbW7MM3LGVYvlcAGvI1+ut7MV3CwRI9loGIlonBWVx65n9wNOeD4rHh4bhY79SV5GCc8JaXcozrhAIuZY+kt9J/Z93I055cqqmkoCUUBpvsT34tC38ddfEz2O3OuHVtPlu5mB0xDVbYQw8wkbIEa91WvpWAVWe+2M2D2RjuLg+GLZKecBPs3lHJQ3gCpU3I+V/EkVhGFndadKpAvAefMLmx9xIX3eP/JEAdemrRTxgKqpAd60Ae36EeRJIQmvKN4dFLRp7oRUKX6kWZ8+xm1QL68qZKJKrezrnK+T+Tb/mjuuqlPpmt/f97mfVl7vBZKGfXkJWkE4SphMHozs51k2MavDzq1WQfLSoSOcbDWjLtR5EWDrw4wVDej8oqkDQc7kGUnF4ZLvhFSZl0kbAEb+MEWrGrKqv+x9CWttrhSmQGbmBNvUJO/3jaJMobtNeWOWyu8Q6qp31IiyBMz2TWuJdGsE7RKlY6oJO9r4Ak4Ap+58rVyuiFVdw2KuGUaJPHZnJED4AhMmwlxyOAgwrr");

        rootCa = DSSUtils.loadCertificateFromBase64EncodedString("MIID+jCCAuKgAwIBAgICB9IwDQYJKoZIhvcNAQENBQAwUTEUMBIGA1UEAwwLZXh0ZXJuYWwtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMTAxMjAwOTQ1MzVaFw0yMzAxMjAwOTQ1MzVaMFAxEzARBgNVBAMMCmNjLXJvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN0d39RQA2CU27QZ4mU/jpBC7hyq1fdb+eO2ezhrLqmlqu17jYyuXqFqXU2F+rSPs1ce8EVo8dQ6E2qDWhmaZr+J6yh8izt1sSZqX5uJWZGrLVc84EynHo/7sAUrsjH+CgqOlhSeQr4gh6Yb7xLnJyVewrqbMR+orV+stvFHfIvsPX0S68norjpiZO+P6gt2lq3hx4XtiiJC+fdyctNMN1tAJKgUqtshSK0WqLc0PbZonktX33bsbFbE+vB4KRLEf9kr4yJN33kUw66kHPagh+2vcyfDFmmF0u4iJOabvXnLkt91VkDR/dK8vpxq2I+tskvoFFbrqAoOeYDiAe8KEo8CAwEAAaOB3DCB2TAOBgNVHQ8BAf8EBAMCAQYwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2V4dGVybmFsLWNhLmNybDBQBggrBgEFBQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9leHRlcm5hbC1jYS5jcnQwHQYDVR0OBBYEFAtZgMyivouroGU+EABbmvHnLIiSMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAI5AakP2fTSPqq5Vpb5rF4Fl38kAcRLNUvZRpPwZJ7D2XNQsxUopx5vGohb5agTNgY1S2MoSJ5E6hUVeStAH9gLzJsuOVwecYaczMRNmrbrUYfZX0Ralg0me4GfQ9S9mulvmYHEyFAWw+QwGq7TxgI45gX05BAH2dvRL5c6DOrWChT87e8lTqCEiX08GWllv1+jADRVfaLo6vxQHXF4x+uo6gp6tPVm9JFRU0Hs59xbu4iLLrXTVdKi0cYgNQYHMJF56BeWt5njEa/bc9+cMbpHnJzV9pcLtBGtEpyZxmMn0NHdz4Ffpbpcwa6mlzS+/7erikn1jzUN0IHBoygxPDqA=");
        externalCa = DSSUtils.loadCertificateFromBase64EncodedString("MIIECjCCAvKgAwIBAgICB9EwDQYJKoZIhvcNAQENBQAwVjEZMBcGA1UEAwwQZXh0ZXJuYWwtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIxMDEyMDA5NDUzNVoXDTIzMDEyMDA5NDUzNVowUTEUMBIGA1UEAwwLZXh0ZXJuYWwtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKnW5Z/B54MMtT42xIBrmZAORzTW0PgJBzgS5NSvvp53fQeMEIg6btkHml3L9WeY/vw8YlBLWhn76vvtfQ3gSZCJYxxFFgJxPfOrg25X1dOj7edUQl/LsbLzjtm6/bi916k8LRmVaRO05H377LeyzRCthlQtbGWd01fly3f5nx7n0WCg+Mp0k4YHZHU6SyaDl0c+IzJvqfIfC94eKoKpTdHZjWSFIVxmpvwuxPwIhLRpsG+D3HjcRq51YF+uYJKV3/w/5732kmDvzmvGL5kXnuaqZ4O8q0EWIXWUcJGdQSqWbXvt8JEtiTpsYpUDjjwJNUvAGvtOoe858eXhrCQHa3MCAwEAAaOB5jCB4zAOBgNVHQ8BAf8EBAMCAQYwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2V4dGVybmFsLXJvb3QtY2EuY3JsMFUGCCsGAQUFBwEBBEkwRzBFBggrBgEFBQcwAoY5aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2V4dGVybmFsLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBSm/EpVPGOTdH2YlhPla5vN8DYiqDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQAgBeg6BXiKETukrlj/zMCqimns0Tp+4ZWgjTt94oF2EGpLlOPCFBp+VyN+z8McNB5YxwnWNQVlKYXe1NXZpSyHlEOkuKgfeqe1FoaTWSGbUvaKqTkSRZOjo8c4m/0aPGY98Gs7QgwSrTSWrG1vPeyG0YwkXb3FTwypo/iOHO226Pfa19HSgF3gros0TiD4h59CKcvLwJi6l6GUMieyNqk1Tug0O8uWPQmZGOY+0uFk/Mh+LxXz7qguseLSDEzqU0wOi5KSdxT73B4aHoagKn4m9K3qVFyyEB/gve3pTxYTr4nQo/MU522mFEyEAQJ7YEdVKaq8NvswhQCO4P3AIDBD");
        externalCaAlternative = DSSUtils.loadCertificateFromBase64EncodedString("MIIEFjCCAv6gAwIBAgICB9QwDQYJKoZIhvcNAQENBQAwVjEZMBcGA1UEAwwQZXh0ZXJuYWwtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIxMDEyMDA5NDUzNVoXDTIzMDEyMDA5NDUzNVowXTEgMB4GA1UEAwwXZXh0ZXJuYWwtY2EtYWx0ZXJuYXRpdmUxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKnW5Z/B54MMtT42xIBrmZAORzTW0PgJBzgS5NSvvp53fQeMEIg6btkHml3L9WeY/vw8YlBLWhn76vvtfQ3gSZCJYxxFFgJxPfOrg25X1dOj7edUQl/LsbLzjtm6/bi916k8LRmVaRO05H377LeyzRCthlQtbGWd01fly3f5nx7n0WCg+Mp0k4YHZHU6SyaDl0c+IzJvqfIfC94eKoKpTdHZjWSFIVxmpvwuxPwIhLRpsG+D3HjcRq51YF+uYJKV3/w/5732kmDvzmvGL5kXnuaqZ4O8q0EWIXWUcJGdQSqWbXvt8JEtiTpsYpUDjjwJNUvAGvtOoe858eXhrCQHa3MCAwEAAaOB5jCB4zAOBgNVHQ8BAf8EBAMCAQYwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2V4dGVybmFsLXJvb3QtY2EuY3JsMFUGCCsGAQUFBwEBBEkwRzBFBggrBgEFBQcwAoY5aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2V4dGVybmFsLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBSm/EpVPGOTdH2YlhPla5vN8DYiqDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQCdjV2nZI/5TpAMxDnnPPqTvrv1HLIbeaPwDzO8MPuzAQAiNCFs9KQv4Bg6tdOI2WWfJPHhwkID41wq9RCTtoAufZ6ctPE3wRVVjRM6uwIYtD32K3PZ3e0XDIRDd1WiOG6qEsPhoE+b7JBV6spSKfm7tvbAoTv85JSBM2HtH4qvJ2aOULqykvfA8CKRzinkdPkCCqWvHqBReO4bKyJCsMUyMb3ARoG73JSzK4vvuft/kvSU/LA1JqFRfF+9W9j2c3iZAyfvvR97kvhJnKtGf5nI154z9qPPAfMPOa0jjoSPXgpqz/Az+kKoPuT8UyBwCWtdcsGK3rPciTzpLe4sfCol");
    }

    @Test
    public void test() {
        ExecutorService executor = Executors.newFixedThreadPool(100);

        List<Future<TestConcurrent.Result>> futures = new ArrayList<>();

        for (int i = 0; i < 1000; i++) {
            futures.add(executor.submit(new TestConcurrent()));
        }

        TestConcurrent.Result result;
        for (Future<TestConcurrent.Result> future : futures) {
            try {
                result = future.get();
                assertTrue(future.isDone());
                validate(result);

            } catch (Exception e) {
                fail(e);
            }
        }

        assertEquals(1000, futures.size());

        executor.shutdown();
    }

    private void validate(TestConcurrent.Result result) {
        for (CertificateToken certificateToken : result.nullableResults) {
            assertNull(certificateToken);
        }
        assertEquals(certificateToken1, result.certificateToken1);
        assertEquals(certificateToken2, result.certificateToken2);
        assertEquals(certificateToken3, result.certificateToken3);
        assertEquals(certificateToken4, result.certificateToken4);

        assertEquals(3, result.externalCa.size());
        for (CertificateToken certificateToken : result.externalCa) {
            assertEquals(externalCa, certificateToken);
        }

        assertEquals(1, result.externalCaAlternative.size());
        for (CertificateToken certificateToken : result.externalCaAlternative) {
            assertEquals(externalCaAlternative, certificateToken);
        }
    }

    private static class TestConcurrent implements Callable<TestConcurrent.Result> {

        @Override
        public Result call() throws Exception {
            Result result = new Result();

            List<CertificateToken> candidates = Arrays.asList(certificateToken1, certificateToken2, certificateToken3, certificateToken4);

            result.nullableResults.add(new TokenIssuerSelector(certificateToken1, candidates).getIssuer());
            result.nullableResults.add(new TokenIssuerSelector(certificateToken2, candidates).getIssuer());
            result.nullableResults.add(new TokenIssuerSelector(certificateToken3, Arrays.asList(certificateToken4)).getIssuer());
            result.nullableResults.add(new TokenIssuerSelector(certificateToken3, null).getIssuer());
            result.nullableResults.add(new TokenIssuerSelector(certificateToken3, Collections.emptyList()).getIssuer());

            result.certificateToken1 = new TokenIssuerSelector(certificateToken3, Arrays.asList(certificateToken1, certificateToken2, certificateToken4)).getIssuer();
            result.certificateToken2 = new TokenIssuerSelector(certificateToken3, Arrays.asList(certificateToken2, certificateToken4)).getIssuer();
            result.certificateToken3 = new TokenIssuerSelector(certificateToken3, candidates).getIssuer();
            result.certificateToken4 = new TokenIssuerSelector(certificateToken4, candidates).getIssuer();

            result.externalCa.add(new TokenIssuerSelector(rootCa, Arrays.asList(externalCa)).getIssuer());
            result.externalCa.add(new TokenIssuerSelector(rootCa, Arrays.asList(externalCa, externalCaAlternative)).getIssuer());
            result.externalCa.add(new TokenIssuerSelector(rootCa, Arrays.asList(externalCaAlternative, externalCa)).getIssuer());

            result.externalCaAlternative.add(new TokenIssuerSelector(rootCa, Arrays.asList(externalCaAlternative)).getIssuer());

            return result;
        }

        private static class Result {

            private List<CertificateToken> nullableResults = new ArrayList<>();

            private CertificateToken certificateToken1;
            private CertificateToken certificateToken2;
            private CertificateToken certificateToken3;
            private CertificateToken certificateToken4;

            private List<CertificateToken> externalCa = new ArrayList<>();
            private List<CertificateToken> externalCaAlternative = new ArrayList<>();

        }

    }

}
