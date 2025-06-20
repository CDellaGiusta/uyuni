/*
 * Copyright (c) 2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */

package com.suse.manager.errata.advisorymap;

import com.redhat.rhn.common.hibernate.HibernateFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class ErrataAdvisoryMapFactory extends HibernateFactory {

    private static final Logger LOG = LogManager.getLogger(ErrataAdvisoryMapFactory.class);

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    /**
     * Save a {@link ErrataAdvisoryMap} object
     *
     * @param advisoryMapEntryIn object to save
     */
    public void save(ErrataAdvisoryMap advisoryMapEntryIn) {
        saveObject(advisoryMapEntryIn);
    }

    /**
     * Remove a {@ink ErrataAdvisoryMap} object
     *
     * @param advisoryMapEntryIn the object to remove
     */
    public void remove(ErrataAdvisoryMap advisoryMapEntryIn) {
        removeObject(advisoryMapEntryIn);
    }


    /**
     * Retrieves the ErrataAdvisoryMap item with the given advisory
     *
     * @param advisory the advisory to look for
     * @return the ErrataAdvisoryMap item instance, if present
     */
    public ErrataAdvisoryMap lookupByAdvisory(String advisory) {
        return getSession()
                .createQuery("FROM ErrataAdvisoryMap k WHERE k.advisory = :advisory", ErrataAdvisoryMap.class)
                .setParameter("advisory", advisory)
                .uniqueResult();
    }

    /**
     * Count the existing table entries
     *
     * @return the current number of table entries
     */
    public long count() {
        return getSession()
                .createQuery("SELECT COUNT(*) FROM ErrataAdvisoryMap k", Long.class)
                .uniqueResult();
    }

    /**
     * Clear all repositories from the database.
     */
    public void clearErrataAdvisoryMap() {
        getSession().createNativeQuery("DELETE FROM suseErrataAdvisoryMap").executeUpdate();
    }

    /**
     * TO BE REMOVED
     *
     * @param advisoryMapList the list of objects to save
     */
    public void populateErrataAdvisoryMapFirstAttemptWillBeRemoved(List<ErrataAdvisoryMap> advisoryMapList) {
        if (0 == count()) {
            //first time populating database
            //this takes about 20 seconds for 140596 records
            advisoryMapList.forEach(this::save);
            return;
        }

        advisoryMapList.forEach(advisoryMapItem -> {
            //this takes more than 45 minutes for 140596 records
            ErrataAdvisoryMap advisoryMapTableEntry = lookupByAdvisory(advisoryMapItem.getAdvisory());

            if (advisoryMapItem.equals(advisoryMapTableEntry)) {
                //there is already an equal record, nothing to do
                return;
            }

            if (null == advisoryMapTableEntry) {
                //new added record
                advisoryMapTableEntry = advisoryMapItem;
            }
            else {
                //update existing record
                advisoryMapTableEntry.setAnnouncementId(advisoryMapItem.getAnnouncementId());
                advisoryMapTableEntry.setAdvisoryUri(advisoryMapItem.getAdvisoryUri());
            }
            getSession().saveOrUpdate(advisoryMapTableEntry);
        });
    }

}


