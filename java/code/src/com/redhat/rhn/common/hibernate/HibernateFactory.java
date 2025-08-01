/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.common.hibernate;

import com.redhat.rhn.common.db.DatabaseException;
import com.redhat.rhn.common.db.datasource.CallableMode;
import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.db.datasource.ModeFactory;
import com.redhat.rhn.common.db.datasource.SelectMode;

import org.apache.commons.collections.ListUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.Hibernate;
import org.hibernate.HibernateException;
import org.hibernate.LockMode;
import org.hibernate.MappingException;
import org.hibernate.Session;
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.metadata.ClassMetadata;
import org.hibernate.query.Query;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BinaryOperator;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import javax.persistence.FlushModeType;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaDelete;
import javax.persistence.criteria.Root;

/**
 * HibernateFactory - Helper superclass that contains methods for fetching and
 * storing Objects from the DB using Hibernate.
 * <p>
 * Abstract methods define what the subclass must implement to determine what is
 * specific to that Factory's instance.
 */
public abstract class HibernateFactory {

    private static ConnectionManager connectionManager = ConnectionManagerFactory.defaultConnectionManager();
    private static final Logger LOG = LogManager.getLogger(HibernateFactory.class);
    public static final int LIST_BATCH_MAX_SIZE = 1000;

    public static final String ROLLBACK_MSG = "Error during transaction. Rolling back";

    protected HibernateFactory() {
    }

    /**
     * Register a class with HibernateFactory, to give the registered class a
     * chance to modify the Hibernate configuration before creating the
     * SessionFactory.
     * @param c Configurator to override Hibernate configuration.
     */
    public static void addConfigurator(Configurator c) {
        connectionManager.addConfigurator(c);
    }

    /**
     * Close the sessionFactory
     */
    public static void closeSessionFactory() {
        connectionManager.close();
    }

    /**
     * Is the factory closed
     * @return boolean
     */
    public static boolean isClosed() {
        return connectionManager.isClosed();
    }

    /**
     * Create a SessionFactory, loading the hbm.xml files from the default
     * location (com.redhat.rhn.domain).
     */
    public static void createSessionFactory() {
        connectionManager.initialize();
    }

    /**
     * Create a SessionFactory, loading the hbm.xml files from alternate
     * location
     * @param additionalLocation Alternate location for hbm.xml files
     */
    public static void createSessionFactory(String[] additionalLocation) {
        connectionManager.setAdditionalPackageNames(additionalLocation);
        connectionManager.initialize();
    }

    /**
     * Register Prometheus Statistics Collector component name
     * @param componentName Name of the application component which will be added to the metric as the `unit` label
     */
    public static void registerComponentName(String componentName) {
        connectionManager.setComponentName(componentName);
    }

    /**
     * Get the Logger for the derived class so log messages show up on the
     * correct class
     * @return Logger for this class.
     */
    protected abstract Logger getLogger();

    /**
     * Binds the values of the map to a named query parameter, whose value
     * matches the key in the given Map, guessing the Hibernate type from the
     * class of the given object.
     * @param query Query to be modified.
     * @param parameters named query parameters to be bound.
     * @throws HibernateException if there is a problem with updating the Query.
     * @throws ClassCastException if the key in the given Map is NOT a String.
     */
    private <T> void bindParameters(Query<T> query, Map<String, Object> parameters)
        throws HibernateException {
        if (parameters == null) {
            return;
        }

        for (Map.Entry<String, Object> entry: parameters.entrySet()) {
            if (entry.getValue() instanceof Collection c) {
                if (c.size() > 1000) {
                    LOG.error("Query executed with Collection larger than 1000");
                }
                query.setParameterList(entry.getKey(), c);
            }
            else {
                query.setParameter(entry.getKey(), entry.getValue());
            }
        }
    }

    /**
     * Finds a single instance of a persistent object given a named query.
     * @param qryName The name of the query used to find the persistent object.
     * It should be formulated to ensure a single object is returned or an error
     * will occur.
     * @param qryParams Map of named bind parameters whose keys are Strings. The
     * map can also be null.
     * @return Object found by named query or null if nothing found.
     */
    protected <T> T lookupObjectByNamedQuery(String qryName, Map<String, Object> qryParams) {
        return lookupObjectByNamedQuery(qryName, qryParams, false);
    }

    /**
     * Finds a single instance of a persistent object given a named query.
     * @param qryName The name of the query used to find the persistent object.
     * It should be formulated to ensure a single object is returned or an error
     * will occur.
     * @param qryParams Map of named bind parameters whose keys are Strings. The
     * map can also be null.
     * @param cacheable if we should cache the results of this object
     * @return Object found by named query or null if nothing found.
     */
    @SuppressWarnings("unchecked")
    protected <T> T lookupObjectByNamedQuery(String qryName, Map<String, Object> qryParams,
            boolean cacheable) {
        try {
            Session session = HibernateFactory.getSession();

            Query<T> query = session.getNamedQuery(qryName).setCacheable(cacheable);
            bindParameters(query, qryParams);
            return query.uniqueResult();
        }
        catch (MappingException me) {
            throw new HibernateRuntimeException("Mapping not found for " + qryName, me);
        }
        catch (HibernateException he) {
            throw new HibernateRuntimeException("Executing query " + qryName +
                    " with params " + qryParams + " failed", he);
        }
    }

    /**
     * Using a named query, find all the objects matching the criteria within.
     * Warning: This can be very expensive if the returned list is large. Use
     * only for small tables with static data
     * @param qryName Named query to use to find a list of objects.
     * @param qryParams Map of named bind parameters whose keys are Strings. The
     * map can also be null.
     * @return List of objects returned by named query, or null if nothing
     * found.
     */
    protected <T> List<T> listObjectsByNamedQuery(String qryName, Map<String, Object> qryParams) {
        return listObjectsByNamedQuery(qryName, qryParams, false);
    }

    /**
     * Using a named query, find all the objects matching the criteria within.
     * Warning: This can be very expensive if the returned list is large. Use
     * only for small tables with static data
     * @param qryName Named query to use to find a list of objects.
     * @param qryParams Map of named bind parameters whose keys are Strings. The
     * map can also be null.
     * @param col the collection to use as an inclause
     * @param colLabel the label the collection will have
     * @return List of objects returned by named query, or null if nothing
     * found.
     */
    protected <T> List<T> listObjectsByNamedQuery(String qryName, Map<String, Object> qryParams,
                                        Collection<Long> col, String colLabel) {

        if (col.isEmpty()) {
            return Collections.emptyList();
        }

        List<Long> tmpList = new ArrayList<>(col);
        List<T> toRet = new ArrayList<>();

        for (int i = 0; i < col.size();) {
            int fin = Math.min(i + 500, col.size());
            List<Long> sublist = tmpList.subList(i, fin);

            Map<String, Object> params = new HashMap<>(qryParams);
            params.put(colLabel, sublist);
            toRet.addAll(listObjectsByNamedQuery(qryName, params, false));
            i = fin;
        }
        return toRet;
    }



    /**
     * Using a named query, find all the objects matching the criteria within.
     * Warning: This can be very expensive if the returned list is large. Use
     * only for small tables with static data
     * @param qryName Named query to use to find a list of objects.
     * @param qryParams Map of named bind parameters whose keys are Strings. The
     * map can also be null.
     * @param cacheable if we should cache the results of this query
     * @return List of objects returned by named query, or null if nothing
     * found.
     */
    @SuppressWarnings("unchecked")
    protected <T> List<T> listObjectsByNamedQuery(String qryName, Map<String, Object> qryParams, boolean cacheable) {
        Session session = HibernateFactory.getSession();
        Query<T> query = session.getNamedQuery(qryName);
        query.setCacheable(cacheable);
        bindParameters(query, qryParams);
        return query.list();
    }

    /**
     * Saves the given object to the database using Hibernate.
     * @param toSave Object to be persisted.
     * @param saveOrUpdate true if saveOrUpdate should be called, false if
     * save() is to be called directly.
     */
    protected void saveObject(Object toSave, boolean saveOrUpdate) {
        Session session = null;
        session = HibernateFactory.getSession();
        if (saveOrUpdate) {
            session.saveOrUpdate(toSave);
        }
        else {
            session.save(toSave);
        }
    }

    /**
     * Saves the given object to the database using Hibernate.
     * @param toSave Object to be persisted.
     */
    protected void saveObject(Object toSave) {
        saveObject(toSave, true);
    }

    /**
     * Remove a Session from the DB
     * @param toRemove Object to be removed.
     * @return int number of objects affected.
     */
    protected int removeObject(Object toRemove) {
        Session session = null;
        int numDeleted = 0;
        session = HibernateFactory.getSession();

        session.delete(toRemove);
        numDeleted++;

        return numDeleted;
    }

    /**
     * Deletes rows corresponding to multiple objects (as in DELETE FROM... IN ...).
     *
     * @param objects the objects to delete
     * @param clazz class of the objects to delete
     * @param <T> type of the objects to delete
     * @return the number of deleted objects
     */
    public static <T> int delete(Collection<T> objects, Class<T> clazz) {
        // both T and clazz are needed because type erasure
        if (objects.isEmpty()) {
            return 0;
        }
        CriteriaBuilder builder = getSession().getCriteriaBuilder();
        CriteriaDelete<T> delete = builder.createCriteriaDelete(clazz);
        Root<T> root = delete.from(clazz);
        delete.where(root.in(objects));
        return getSession().createQuery(delete).executeUpdate();
    }

    /**
     * Returns the Hibernate session stored in ThreadLocal storage. If not
     * present, creates a new one and stores it in ThreadLocal; creating the
     * session also begins a transaction implicitly.
     *
     * @return Session Session asked for
     */
    public static Session getSession() {
        return connectionManager.getSession();
    }

    /**
     * Returns the Hibernate session stored in ThreadLocal storage, if it exists
     *
     * @return Session a session
     */
    public static Optional<Session> getSessionIfPresent() {
        return connectionManager.getSessionIfPresent();
    }

    /**
     * Commit the transaction for the current session. This method or
     * {@link #rollbackTransaction}can only be called once per session.
     *
     * @throws HibernateException if the commit fails
     */
    public static void commitTransaction() throws HibernateException {
        connectionManager.commitTransaction();
    }

    /**
     * Roll back transaction in case it is not committed and close the Hibernate session.
     *
     * @param committed - if it was possible to commit the transaction.
     */
    public static void rollbackTransactionAndCloseSession(boolean committed) {
        try {
            if (!committed) {
                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Rolling back transaction");
                    }
                    HibernateFactory.rollbackTransaction();
                }
                catch (HibernateException e) {
                    final String msg = "Additional error during rollback";
                    LOG.warn(msg, e);
                }
            }
        }
        finally {
            // cleanup the session
            HibernateFactory.closeSession();
        }
    }

    /**
     * Roll the transaction for the current session back. This method or
     * {@link #commitTransaction}can only be called once per session.
     *
     * @throws HibernateException if the commit fails
     */
    public static void rollbackTransaction() throws HibernateException {
        connectionManager.rollbackTransaction();
    }

    /**
     * Is transaction pending for thread?
     * @return boolean
     */
    public static boolean inTransaction() {
        return connectionManager.isTransactionPending();
    }

    /**
     * Closes the Hibernate Session stored in ThreadLocal storage.
     */
    public static void closeSession() {
        connectionManager.closeSession();
    }

    /**
     * Return the persistent instance of the given entity class with the given
     * identifier, or null if there is no such persistent instance. (If the
     * instance, or a proxy for the instance, is already associated with the
     * session, return that instance or proxy.)
     * @param clazz a persistent class
     * @param id an identifier
     * @return Object persistent instance or null
     */
    public Object getObject(Class clazz, Serializable id) {
        Object retval = null;
        Session session = null;

        try {
            session = HibernateFactory.getSession();

            retval = session.get(clazz, id);
        }
        catch (MappingException me) {
            getLogger().error("Mapping not found for {}", clazz.getName(), me);

        }
        catch (HibernateException he) {
            getLogger().error("Hibernate exception: {}", he.toString());
        }

        return retval;
    }

    /**
     * Return a locked persistent instance of the given entity class with
     * the given identifier, or null if there is no such persistent instance.
     * (If the instance, or a proxy for the instance, is already associated
     * with the session, return that instance or proxy.)
     * @param clazz a persistent class
     * @param id an identifier
     * @return Object persistent instance or null
     */
    protected Object lockObject(Class clazz, Serializable id) {
        Object retval = null;
        Session session = null;

        try {
            session = HibernateFactory.getSession();

            retval = session.get(clazz, id, LockMode.PESSIMISTIC_WRITE);
        }
        catch (MappingException me) {
            getLogger().error("Mapping not found for {}", clazz.getName(), me);

        }
        catch (HibernateException he) {
            getLogger().error("Hibernate exception: {}", he.toString());
        }

        return retval;
    }

    /**
     * Util to reload an object using Hibernate
     * @param obj to be reloaded
     * @return Object found if not, null
     * @throws HibernateException if something bad happens.
     * @param <T> the entity type
     */
    public static <T> T reload(T obj) throws HibernateException {
        ClassMetadata cmd = connectionManager.getMetadata(obj);
        Serializable id = cmd.getIdentifier(obj, (SessionImplementor) getSession());
        Session session = getSession();
        session.flush();
        session.evict(obj);
        /*
         * In hibernate 3, the following doesn't work:
         * session.load(obj.getClass(), id)
         * load returns the proxy class instead of the persisted class, ie,
         * Filter$$EnhancerByCGLIB$$9bcc734d_2 instead of Filter.
         * session.get is set to not return the proxy class, so that is what we'll use.
         */
        return (T) session.get(obj.getClass(), id);
    }

    /**
     * utility to convert blob to byte array
     * @param fromBlob blob to convert
     * @return byte array converted from blob
     */
    public static byte[] blobToByteArray(Blob fromBlob) {

        if (fromBlob == null) {
            return new byte[0];
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream is = fromBlob.getBinaryStream()) {
            IOUtils.copy(is, baos, 4000);
            return baos.toByteArray();
        }
        catch (SQLException e) {
            LOG.error("SQL Error converting blob to byte array", e);
            throw new DatabaseException(e.toString(), e);
        }
        catch (IOException e) {
            LOG.error("I/O Error converting blob to byte array", e);
            throw new DatabaseException(e.toString(), e);
        }
    }

    /**
     * Get the String version of the byte array contents
     * used to return the string representation of byte arrays constructed from blobs
     * @param barr byte array to convert to String
     * @return String version of the byte array contents
     */
    public static String getByteArrayContents(byte[] barr) {

        String retval = "";

        if (barr != null) {
            retval = new String(barr, StandardCharsets.UTF_8);
        }
        return retval;
    }

    /**
     * Get the String version of an object corresponding to a BLOB column
     * Handles both the byte[] and the Blob cases
     * @param blob the blob to handle
     * @return String version of the blob contents, null if the blob was null
     * or if the specified object is not actually a Blob
     */
    public static String getBlobContents(Object blob) {
        // Returned by Hibernate, and also returned by mode queries
        // from an Oracle database
        if (blob instanceof byte[] byt) {
            return getByteArrayContents(byt);
        }
        // Returned only by mode queries from a Postgres database
        if (blob instanceof Blob blb) {
            return getByteArrayContents(blobToByteArray(blb));
        }
        return null;
    }

    /**
     * Convert a byte[] array to a Blob object.  Guards against
     * null arrays and 0 length arrays.
     * @param data array to convert to a Blob
     * @return Blob if data[] is non-null and {@literal length > 0}, null otherwise
     */
    public static Blob byteArrayToBlob(byte[] data) {
        if (data == null) {
            return null;
        }
        if (data.length == 0) {
            return null;
        }
        return Hibernate.getLobCreator(getSession()).createBlob(data);

    }

    /**
     * Convert a String to a byte[] object.  Guards against
     * null arrays and 0 length arrays.
     * @param data string to convert to a Blob
     * @return Blob if data[] is non-null and {@literal length > 0}, null otherwise
     */
    public static byte[] stringToByteArray(String data) {
        if (StringUtils.isEmpty(data)) {
            return null;
        }

        return data.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Initialize the underlying db layer
     *
     */
    public static void initialize() {
        connectionManager.initialize();
    }

    /**
     * Disables Hibernate's automatic flushing, runs <code>body</code>, and then
     * enables it again. Returns the result from <code>body</code>.
     *
     * You might want this in order to improve performance by skipping automatic
     * flushes, which might be costly if the number of objects in the Hibernate
     * cache is high. As of hibernate 5.1 the algorithm is quadratic in the
     * number of objects.
     *
     * WARNING: this might result in queries returning stale data -
     * modifications to Hibernate objects before or in this call will not be
     * seen by queries called from <code>body</code>!
     *
     * Only use with code that does not make assumptions about Hibernate cache
     * modifications being reflected in the database. Also it is recommended to
     * make sure via profiling that your method is spending too much CPU time in
     * automatic flushing before attempting to use this method.
     *
     * @param body code to run in FlushModeType.COMMIT
     * @param <T> return type
     * @return the value of supplier
     */
    public static <T> T doWithoutAutoFlushing(Supplier<T> body) {
        return doWithoutAutoFlushing(body, true);
    }

    /**
     * Disables Hibernate's automatic flushing, runs <code>body</code>, and then
     * enables it again. Returns the result from <code>body</code>.
     *
     * You might want this in order to improve performance by skipping automatic
     * flushes, which might be costly if the number of objects in the Hibernate
     * cache is high. As of hibernate 5.1 the algorithm is quadratic in the
     * number of objects.
     *
     * WARNING: this might result in queries returning stale data -
     * modifications to Hibernate objects before or in this call will not be
     * seen by queries called from <code>body</code>!
     *
     * Only use with code that does not make assumptions about Hibernate cache
     * modifications being reflected in the database. Also it is recommended to
     * make sure via profiling that your method is spending too much CPU time in
     * automatic flushing before attempting to use this method.
     *
     * Optionally do not open a session if one does not exist.
     *
     * @param <T> return type
     * @param body code to run in FlushModeType.COMMIT
     * @param createSession whether to create a session if one does not exist
     * @return the value of supplier
     */
    public static <T> T doWithoutAutoFlushing(Supplier<T> body, boolean createSession) {
        Optional<Session> session = getSessionIfPresent();
        if (!session.isPresent() && !createSession) {
            return body.get();
        }

        FlushModeType old = getSession().getFlushMode();
        getSession().setFlushMode(FlushModeType.COMMIT);
        try {
            return body.get();
        }
        finally {
            getSession().setFlushMode(old);
        }
    }

    /**
     * Disables Hibernate's automatic flushing, runs <code>body</code>, and then
     * enables it again.
     *
     * You might want this in order to improve performance by skipping automatic
     * flushes, which might be costly if the number of objects in the Hibernate
     * cache is high. As of Hibernate 5.1 the algorithm is quadratic in the
     * number of objects.
     *
     * WARNING: this might result in queries returning stale data -
     * modifications to Hibernate objects before or in this call will not be
     * seen by queries called from <code>body</code>!
     *
     * Only use with code that does not make assumptions about Hibernate cache
     * modifications being reflected in the database. Also it is recommended to
     * make sure via profiling that your method is spending too much CPU time in
     * automatic flushing before attempting to use this method.
     *
     * @param body code to run in FlushModeType.COMMIT
     */
    public static void doWithoutAutoFlushing(Runnable body) {
        doWithoutAutoFlushing(body, true);
    }

    /**
     * Disables Hibernate's automatic flushing, runs <code>body</code>, and then
     * enables it again.
     *
     * You might want this in order to improve performance by skipping automatic
     * flushes, which might be costly if the number of objects in the Hibernate
     * cache is high. As of Hibernate 5.1 the algorithm is quadratic in the
     * number of objects.
     *
     * WARNING: this might result in queries returning stale data -
     * modifications to Hibernate objects before or in this call will not be
     * seen by queries called from <code>body</code>!
     *
     * Only use with code that does not make assumptions about Hibernate cache
     * modifications being reflected in the database. Also it is recommended to
     * make sure via profiling that your method is spending too much CPU time in
     * automatic flushing before attempting to use this method.
     *
     * Optionally do not open a session if one does not exist.
     *
     * @param body code to run in FlushModeType.COMMIT
     * @param createSession whether to create a session if one does not exist
     */
    public static void doWithoutAutoFlushing(Runnable body, boolean createSession) {
        doWithoutAutoFlushing(() -> {
            body.run();
            return 0;
        }, createSession);
    }

    /**
     * Returns the current initialization status
     * @return boolean current status
     */
    public static boolean isInitialized() {
        return connectionManager.isInitialized();
    }

    protected static DataResult executeSelectMode(String name, String mode, Map params) {
        SelectMode m = ModeFactory.getMode(name, mode);
        return m.execute(params);
    }

    protected static void executeCallableMode(String name, String mode, Map params) {
        CallableMode m = ModeFactory.getCallableMode(name, mode);
        m.execute(params, new HashMap<>());
    }

    /**
     * Executes a 'lookup' query to retrieve data from the database given a list of ids.
     * The query will be execute in batches of LIST_BATCH_MAX_SIZE ids each.
     * @param <T> the type of the returned objects
     * @param <ID>
     * @param ids the ids to search for
     * @param queryName the name of the query to be executed
     * @param idsParameterName the name of the parameter to match the ids
     * @return a list of the objects found
     */
    protected static <T, ID> List<T> findByIds(List<ID> ids, String queryName, String idsParameterName) {
        return findByIds(ids, queryName, idsParameterName, new HashMap<>());
    }

    /**
     * Executes an 'update' query to the database given a list of parameters.
     * The query will be executed in batches of LIST_BATCH_MAX_SIZE parameters each.
     * @param <E> the type of the list parameters
     * @param list the list of parameters to search for
     * @param queryName the name of the query to be executed
     * @param parameterName the name of the parameter to match the parameters in the list
     * @return the count of affected rows
     */
    @SuppressWarnings("unchecked")
    protected static <E> int udpateByIds(List<E> list, String queryName, String parameterName,
            Map<String, Object> parameters) {
        Query<Integer> query = HibernateFactory.getSession().getNamedQuery(queryName);

        parameters.entrySet().stream().forEach(entry -> query.setParameter(entry.getKey(), entry.getValue()));

        return splitAndExecuteQuery(list, parameterName, query, query::executeUpdate, 0, Integer::sum);
    }

    /**
     * Executes a 'lookup' query to retrieve data from the database given a list of ids.
     * The query will be execute in batches of LIST_BATCH_MAX_SIZE ids each.
     * @param <T> the type of the returned objects
     * @param <ID> the type of the ids
     * @param ids the ids to search for
     * @param queryName the name of the query to be executed
     * @param idsParameterName the name of the parameter to match the ids
     * @param parameters extra parameters to include in the query
     * @return a list of the objects found
     */
    @SuppressWarnings("unchecked")
    protected static <T, ID> List<T> findByIds(List<ID> ids, String queryName,
            String idsParameterName, Map<String, Object> parameters) {
        Query<T> query = HibernateFactory.getSession().getNamedQuery(queryName);

        parameters.entrySet().stream().forEach(entry -> query.setParameter(entry.getKey(), entry.getValue()));

        return splitAndExecuteQuery(ids, idsParameterName, query, query::getResultList,
                new ArrayList<T>(), ListUtils::union);
    }

    /**
     * Splits a list of elements in batches of LIST_BATCH_MAX_SIZE and execute a query for each batch.
     * Results from each query are reduced via `accumulator` using the provided `identity`.
     * @param <T> the return type
     * @param <E> the type of the elements in the list parameter
     * @param <R> the type of the returned objects by the query
     * @param list the list of parameters to search for
     * @param parameterName the name of the parameter to match the parameters in the list
     * @param query the query to be executed
     * @param queryFunction the function to be call on the query
     * @param identity the identity for the accumulator function
     * @param accumulator the operation for the result accumulator
     * @return an accumulated result of executing the query
     */
    protected static <E, T, R> T splitAndExecuteQuery(List<E> list, String parameterName,
            Query<R> query, Supplier<T> queryFunction, T identity, BinaryOperator<T> accumulator) {
        int size = list.size();

        List<List<E>> batches = IntStream.iterate(0, i -> i < size, i -> i + LIST_BATCH_MAX_SIZE)
                .mapToObj(i -> list.subList(i, Math.min(i + LIST_BATCH_MAX_SIZE, size)))
                .toList();
        return batches.stream()
                .map(b -> {
                    query.setParameterList(parameterName, b);
                    return queryFunction.get();
                })
                .reduce(identity, accumulator::apply);
    }

    /**
     * Loads the full hibernate object in case the object is currently just a proxy
     * @param proxy object to unproxy
     * @param <T> type of the object to unproxy
     * @return the unproxied hibernate object
     */
    @SuppressWarnings("unchecked")
    public static <T> T unproxy(T proxy) {
        return (T) Hibernate.unproxy(proxy);
    }

}
