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
package eu.europa.esig.dss.spi.client.jdbc;

import eu.europa.esig.dss.spi.client.jdbc.query.SqlQuery;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlSelectQuery;
import eu.europa.esig.dss.spi.client.jdbc.record.SqlRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * This class executes calls to a {@code javax.sql.DataSource}
 *
 */
public class JdbcCacheConnector {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheConnector.class);

    /**
     * SQL DataSource to create connection with
     */
    private final DataSource dataSource;

    /**
     * Default constructor
     *
     * @param dataSource {@link DataSource} to connect with
     */
    public JdbcCacheConnector(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * This method allows to execute a query with a custom set of arguments, such as SELECT, UPDATE or DELETE,
     * by handling an exception.
     *
     * @param query {@link SqlQuery} the query
     * @param arguments an array of {@link Object}s, representing the query arguments
     * @return number of rows concerned by the query
     */
    public int execute(final SqlQuery query, Object... arguments) {
        Objects.requireNonNull(query, "Query cannot be null!");

        Connection c = null;
        PreparedStatement s = null;
        try {
            c = dataSource.getConnection();
            c.setAutoCommit(false);

            s = c.prepareStatement(query.getQueryString());
            for (int ii = 0; ii < arguments.length; ii++) {
                s.setObject(ii + 1, arguments[ii]);
            }
            int ii = s.executeUpdate();
            c.commit();
            LOG.debug("The query [{}] has been executed successfully", query);
            return ii;

        } catch (final SQLException e) {
            LOG.error("Unable to execute the query [{}]. Reason : '{}'", query, e.getMessage(), e);
            rollback(c);
            return 0;

        } finally {
            closeQuietly(c, s, null);
        }
    }

    /**
     * This method executes the query and returns a collection of selected objects
     *
     * @param selectQuery {@link SqlSelectQuery} the query to SELECT objects
     * @param arguments an array of {@link Object}s, representing the query arguments
     * @return a collection of {@link SqlRecord}s
     */
    public Collection<SqlRecord> select(final SqlSelectQuery selectQuery, Object... arguments) {
        Connection c = null;
        PreparedStatement s = null;
        ResultSet rs = null;
        try {
            c = dataSource.getConnection();
            c.setAutoCommit(false);

            s = c.prepareStatement(selectQuery.getQueryString());
            for (int ii = 0; ii < arguments.length; ii++) {
                s.setObject(ii + 1, arguments[ii]);
            }
            rs = s.executeQuery();

            final Collection<SqlRecord> records = selectQuery.getRecords(rs);

            c.commit();
            LOG.debug("The SELECT query [{}] has been executed successfully.", selectQuery);
            return records;

        } catch (final SQLException e) {
            LOG.error("Unable to execute query [{}]. Reason : {}", selectQuery, e.getMessage(), e);
            rollback(c);
            return Collections.emptySet();

        } finally {
            closeQuietly(c, s, rs);
        }
    }

    /**
     * This method allows table creation, removal and existence check
     *
     * @param query {@link SqlQuery} the query
     * @return TRUE if the query has been executed successfully, FALSE otherwise
     */
    public boolean tableQuery(final SqlQuery query) {
        Connection c = null;
        Statement s = null;
        try {
            c = dataSource.getConnection();
            c.setAutoCommit(false);

            s = c.createStatement();
            boolean result = s.execute(query.getQueryString());
            c.commit();
            return result;

        } catch (final SQLException e) {
            return false;

        } finally {
            closeQuietly(c, s, null);
        }
    }

    /**
     * This method allows executing of INSERT, UPDATE or DELETE queries, by throwing an exception in case of an error
     *
     * @param query {@link SqlQuery} the query
     * @return number of concerned rows
     * @throws SQLException if an exception occurs
     */
    public int executeThrowable(final SqlQuery query) throws SQLException {
        Connection c = null;
        Statement s = null;
        try {
            c = dataSource.getConnection();
            c.setAutoCommit(false);

            s = c.createStatement();
            int result = s.executeUpdate(query.getQueryString());
            c.commit();
            return result;

        } catch (final SQLException e) {
            rollback(c);
            throw e;

        } finally {
            closeQuietly(c, s, null);
        }
    }

    /**
     * Rollback transaction for the given {@link Connection}
     *
     * @param c {@link Connection}
     */
    protected void rollback(final Connection c) {
        if (c != null) {
            try {
                LOG.warn("Transaction is being rolled back");
                c.rollback();
            } catch (final SQLException e) {
                LOG.error("Unable to rollback", e);
            }
        }
    }

    /**
     * Close the statement and connection and resultset without throwing the exception
     *
     * @param c
     *            the connection
     * @param s
     *            the statement
     * @param rs
     *            the ResultSet
     */
    protected void closeQuietly(final Connection c, final Statement s, final ResultSet rs) {
        closeQuietly(rs);
        closeQuietly(s);
        closeQuietly(c);
    }

    /**
     *  Close the connection without throwing the exception
     *
     * @param c
     * 			the connection
     */
    private void closeQuietly(final Connection c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (final SQLException e) {
            // purposely empty
        }
    }

    /**
     *  Close the statement without throwing the exception
     *
     * @param s
     * 			the statement
     */
    private void closeQuietly(final Statement s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (final SQLException e) {
            // purposely empty
        }
    }

    /**
     *  Close the ResultSet without throwing the exception
     *
     * @param rs
     * 			the ResultSet
     */
    private void closeQuietly(final ResultSet rs) {
        try {
            if (rs != null) {
                rs.close();
            }
        } catch (final SQLException e) {
            // purposely empty
        }
    }

}
