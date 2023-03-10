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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;

/**
 * The SignatureValue
 */
@SuppressWarnings("serial")
public final class SignatureValue implements Serializable {

	/** Used SignatureAlgorithm for signing */
	private SignatureAlgorithm algorithm;

	/** The SignatureValue value */
	private byte[] value;

	/**
	 * Empty constructor
	 */
	public SignatureValue() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param algorithm {@link SignatureAlgorithm}
	 * @param value the SignatureValue binaries
	 */
	public SignatureValue(SignatureAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	/**
	 * Gets the {@code SignatureAlgorithm}
	 *
	 * @return {@link SignatureAlgorithm}
	 */
	public SignatureAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the {@code SignatureAlgorithm}
	 *
	 * @param algorithm {@link SignatureAlgorithm}
	 */
	public void setAlgorithm(SignatureAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Gets the SignatureValue binaries
	 *
	 * @return SignatureValue binaries
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * Sets the SignatureValue binaries
	 *
	 * @param value SignatureValue binaries
	 */
	public void setValue(byte[] value) {
		this.value = value;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((algorithm == null) ? 0 : algorithm.hashCode());
		result = (prime * result) + Arrays.hashCode(value);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SignatureValue other = (SignatureValue) obj;
		if (algorithm != other.algorithm) {
			return false;
		}
		if (!Arrays.equals(value, other.value)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignatureValue [algorithm=" + algorithm + ", value=" + ((value != null) ? Base64.getEncoder().encodeToString(value) : null) + "]";
	}

}
