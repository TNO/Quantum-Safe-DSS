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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class may be used to define a User Notice signature policy qualifier.
 *
 */
public class UserNotice implements Serializable {

    private static final long serialVersionUID = 4637901888995768120L;

    /** The name of the organization */
    private String organization;

    /** Numbers identifying a group of textual statements prepared by the organization */
    private int[] noticeNumbers;

    /** The text of the notice */
    private String explicitText;

    /**
     * Empty constructor
     */
    public UserNotice() {
        // empty constructor
    }

    /**
     * Gets the organization name
     *
     * @return {@link String}
     */
    public String getOrganization() {
        return organization;
    }

    /**
     * Sets the organization name
     *
     * NOTE: when the property is not empty, the {@code noticeNumbers} also shall be set!
     *
     * @param organization {@link String}
     */
    public void setOrganization(String organization) {
        this.organization = organization;
    }

    /**
     * Gets the notice numbers
     *
     * @return an array of {@link Integer}s
     */
    public int[] getNoticeNumbers() {
        return noticeNumbers;
    }

    /**
     * Sets the notice numbers identifying a group of textual statements prepared by the organization
     *
     * NOTE: when the property is not empty, the {@code organization} also shall be set!
     *
     * @param noticeNumbers an array of integers
     */
    public void setNoticeNumbers(int... noticeNumbers) {
        this.noticeNumbers = noticeNumbers;
    }

    /**
     * Gets the notice text
     *
     * @return {@link String}
     */
    public String getExplicitText() {
        return explicitText;
    }

    /**
     * Sets the text of the notice to be displayed
     *
     * @param explicitText {@link String}
     */
    public void setExplicitText(String explicitText) {
        this.explicitText = explicitText;
    }

    /**
     * This method checks if the content of the UserNotice is empty or not
     *
     * @return TRUE if the object is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        if (organization != null && !organization.isEmpty()) {
            return false;
        }
        if (noticeNumbers != null && noticeNumbers.length > 0) {
            return false;
        }
        if (explicitText != null && !explicitText.isEmpty()) {
            return false;
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserNotice)) return false;

        UserNotice that = (UserNotice) o;

        if (!Objects.equals(organization, that.organization)) return false;
        if (!Arrays.equals(noticeNumbers, that.noticeNumbers)) return false;
        return Objects.equals(explicitText, that.explicitText);
    }

    @Override
    public int hashCode() {
        int result = organization != null ? organization.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(noticeNumbers);
        result = 31 * result + (explicitText != null ? explicitText.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "UserNotice {organization='" + organization + "', noticeNumbers=" + Arrays.toString(noticeNumbers) +
                ", explicitText='" + explicitText + "'}";
    }

}
