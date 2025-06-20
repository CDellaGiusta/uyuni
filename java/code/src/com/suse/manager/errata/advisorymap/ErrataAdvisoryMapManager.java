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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ErrataAdvisoryMapManager {

    private final ErrataAdvisoryMapFactory advisoryMapFactory;

    private static final String ADVISORY_MAP_CSV_DELIMITER = ",";

    /**
     * Default constructor
     */
    public ErrataAdvisoryMapManager() {
        this(new ErrataAdvisoryMapFactory());
    }

    /**
     * Builds an instance with the given dependencies
     *
     * @param advisoryMapFactoryIn the errata advisory map factory
     */
    public ErrataAdvisoryMapManager(ErrataAdvisoryMapFactory advisoryMapFactoryIn) {
        this.advisoryMapFactory = advisoryMapFactoryIn;
    }

    /**
     * parses an advisory map csv file
     * <p>
     * the advisory map csv file has the following structure:
     * a) first row has headers
     * b) each row represents an entry
     * c) each entry row contains fields, coma (",") separated
     * d) first field is the advisory (e.g. "SUSE-SLE-Module-Basesystem-15-SP6-2025-1733")
     * e) second field is the announcementId (e.g. "SUSE-RU-2025:01733-1")
     * f) third field (optional) is the advisoryUri
     * (e.g. "https://www.suse.com/support/update/announcement/2025/suse-ru-202501733-1")
     *
     * @param inputStreamIn the errata advisory map input stream
     * @return a list of advisory map items
     */
    public List<ErrataAdvisoryMap> readAdvisoryMap(InputStream inputStreamIn) throws IOException {
        List<ErrataAdvisoryMap> advisoryMapList = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStreamIn))) {
            String line;
            //skip first line
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (!firstLine) {
                    String[] advisoryItem = line.split(ADVISORY_MAP_CSV_DELIMITER);

                    String advisory = (advisoryItem.length > 0 ? advisoryItem[0] : "");
                    String announcementId = (advisoryItem.length > 1 ? advisoryItem[1] : "");
                    String advisoryUri = (advisoryItem.length > 2 ? advisoryItem[2] : "");

                    advisoryMapList.add(new ErrataAdvisoryMap(advisory, announcementId, advisoryUri));
                }
                firstLine = false;
            }
        }
        return advisoryMapList;
    }

    /**
     * parses an advisory map csv file
     *
     * @param advisoryMapFileName the errata advisory map csv file name
     * @return a list of advisory map items
     */
    public List<ErrataAdvisoryMap> readAdvisoryMap(String advisoryMapFileName) throws IOException {
        File advisoryMapFile = new File(advisoryMapFileName);
        InputStream inputStream = new FileInputStream(advisoryMapFile);
        return readAdvisoryMap(inputStream);
    }

    /**
     * Populate database with a new advisory map
     *
     * @param advisoryMapList the new advisory map to save
     */
    public void populateErrataAdvisoryMap(List<ErrataAdvisoryMap> advisoryMapList) {
        if (advisoryMapList.isEmpty()) {
            return;
        }
        if (advisoryMapList.size() < advisoryMapFactory.count()) {
            //this is to ensure that new advisory map is considered only if equal or incremental
            //do we really need this check?
            return;
        }
        advisoryMapFactory.clearErrataAdvisoryMap();
        advisoryMapList.forEach(advisoryMapFactory::save);
    }
}
