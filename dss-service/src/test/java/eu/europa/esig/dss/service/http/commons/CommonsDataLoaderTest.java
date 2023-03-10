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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader.DataAndUrl;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CommonsDataLoaderTest {

	private static final Logger LOG = LoggerFactory.getLogger(CommonsDataLoaderTest.class);

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

	private CommonsDataLoader dataLoader;

	@BeforeEach
	public void init() {
		dataLoader = new CommonsDataLoader();
	}

	@Test
	public void testGet() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		NativeHTTPDataLoader dataLoader2 = new NativeHTTPDataLoader();
		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD);

		assertArrayEquals(bytesArray, bytesArrays2);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void ldapTest1() {
		String url = "ldap://x500.gov.si/ou=sigen-ca,o=state-institutions,c=si?certificateRevocationList?base";
		getDataAndAssertNotNull(url);
	}

	@Test
	public void ldapTest2() {
		String url = "ldap://postarca.posta.si/ou=POSTArCA,o=POSTA,c=SI?certificateRevocationList";
		getDataAndAssertNotNull(url);
	}

	@Test
	public void ldapTest3() {
		String url = "ldap://acldap.nlb.si/o=ACNLB,c=SI?certificateRevocationList";
		getDataAndAssertNotNull(url);
	}

	@Test
	public void dss1583test() {
		String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems%20International%20GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH%20,%20c=de%20";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH , c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificateRevocationList?base";
		getDataAndAssertNotNull(url);
	}

	private void getDataAndAssertNotNull(String url) {
		try {
			assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		} catch (DSSExternalResourceException e) {
			LOG.error("Failed to obtain data from an external source. Reason : [{}]", e.getMessage());
		}
	}

	@Test
	public void dss1583WarningTest() {
		assertThrows(DSSException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de%2";
			dataLoader.get(url);
		});
		assertThrows(DSSException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Syste%ms International GmbH,c=de";
			dataLoader.get(url);
		});
		assertThrows(DSSException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-SystemsInternational GmbH,c=de";
			dataLoader.get(url);
		});
		assertThrows(DSSException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificate";
			dataLoader.get(url);
		});
	}

	@Test
	public void timeoutTest() {
		dataLoader.setTimeoutConnection(1);
		DSSExternalResourceException exception = assertThrows(DSSExternalResourceException.class,
				() -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [" + URL_TO_LOAD + "]"));

		dataLoader.setTimeoutConnection(60000);
		dataLoader.setTimeoutResponse(1);
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [" + URL_TO_LOAD + "]"));
	}

	@Test
	public void resourceDoesNotExistTest() {
		dataLoader.setTimeoutConnection(1);
		DSSExternalResourceException exception = assertThrows(DSSExternalResourceException.class,
				() -> dataLoader.get("http://wrong.url"));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [http://wrong.url]"));
	}

	@Test
	public void multipleDataLoadTest() {
		byte[] firstUrlData = dataLoader.get(URL_TO_LOAD);
		DataAndUrl dataAndUrl = dataLoader.get(Arrays.asList(URL_TO_LOAD, "http://ncrl.ssc.lt/class3nqc/cacrl.crl",
				"http://www.ssc.lt/cacert/ssc_class3nqc.crt"));
		assertEquals(URL_TO_LOAD, dataAndUrl.getUrlString());
		assertArrayEquals(firstUrlData, dataAndUrl.getData());

		dataAndUrl = dataLoader.get(Arrays.asList("http://wrong.url", "does_not_exist", URL_TO_LOAD));
		assertEquals(URL_TO_LOAD, dataAndUrl.getUrlString());
		assertTrue(Arrays.equals(firstUrlData, dataAndUrl.getData()));

	}

	@Test
	public void multipleDataLoaderExceptionTest() {
		dataLoader.setTimeoutConnection(1);

		List<String> urls = Arrays.asList("http://wrong.url", "does_not_exist", URL_TO_LOAD);
		DSSDataLoaderMultipleException exception = assertThrows(DSSDataLoaderMultipleException.class,
				() -> dataLoader.get(urls));
		assertTrue(exception.getMessage().contains("http://wrong.url"));
		assertTrue(exception.getMessage().contains("does_not_exist"));
		assertTrue(exception.getMessage().contains(URL_TO_LOAD));
	}

	@Test
	public void negativeTimeoutTest() {
		// negative values enforce to use system properties
		dataLoader.setTimeoutConnection(-1);
		dataLoader.setTimeoutConnectionRequest(-1);
		dataLoader.setTimeoutResponse(-1);
		dataLoader.setTimeoutSocket(-1);
		dataLoader.setConnectionKeepAlive(-1);
		dataLoader.setConnectionTimeToLive(-1);

		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));
	}

	@Test
	public void excludedHostsTest() {
		ProxyProperties proxyProperties = new ProxyProperties();
		proxyProperties.setHost("1.2.4.5.6");
		proxyProperties.setPort(8080);

		ProxyConfig proxyConfig = new ProxyConfig();
		proxyConfig.setHttpProperties(proxyProperties);

		dataLoader.setProxyConfig(proxyConfig);

		Exception exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("certs.eid.belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));
	}

	@Test
	public void httpClientResponseHandlerTest() {
		CommonsHttpClientResponseHandler httpClientResponseHandler = new CommonsHttpClientResponseHandler();
		dataLoader.setHttpClientResponseHandler(httpClientResponseHandler);
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Arrays.asList(HttpStatus.SC_OK));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_CONTINUE));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Arrays.asList(HttpStatus.SC_CONTINUE));
		Exception exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertEquals("Unable to process GET call for url [http://certs.eid.belgium.be/belgiumrs2.crt]. " +
				"Reason : [Not acceptable HTTP Status (HTTP status code : 200 / reason : OK)]", exception.getMessage());
	}

}
