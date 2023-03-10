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
package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.pdf.BaseFont;

import eu.europa.esig.dss.pdf.visible.AbstractDSSFontMetrics;

/**
 * The IText (OpenPDF) implementation of Font metrics
 */
public class ITextDSSFontMetrics extends AbstractDSSFontMetrics {

	/** The OpenPDF font */
	private final BaseFont baseFont;

	/**
	 * Default constructor
	 *
	 * @param baseFont {@link BaseFont}
	 */
	public ITextDSSFontMetrics(BaseFont baseFont) {
		this.baseFont = baseFont;
	}

	@Override
	public float getWidth(String str, float size) {
		return baseFont.getWidthPoint(str, size);
	}

	@Override
	public float getHeight(String str, float size) {
		float ascent = getAscentPoint(str, size);
		float descent = getDescentPoint(str, size);
		return ascent - descent;
	}

	/**
	 * Returns the ascent point
	 *
	 * @param str {@link String} to get value for
	 * @param size the size of the string
	 * @return ascent point
	 */
	public float getAscentPoint(String str, float size) {
		return baseFont.getAscentPoint(str, size);
	}

	/**
	 * Returns the descent point
	 *
	 * @param str {@link String} to get value for
	 * @param size the size of the string
	 * @return descent point
	 */
	public float getDescentPoint(String str, float size) {
		return baseFont.getDescentPoint(str, size);
	}

}
