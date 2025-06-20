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

import org.apache.commons.io.FileUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class ErrataAdvisoryMapManager {

    private final ErrataAdvisoryMapFactory advisoryMapFactory;

    private static final String ADVISORY_MAP_CSV_DELIMITER = ",";
    public static final String ADVISORY_MAP_CSV_SOURCE_URL =
            "https://ftp.suse.com/pub/projects/security/advisory-map.csv";

    protected int connectionTimeoutMs = 15_000;
    protected int readTimeoutMs = 15_000;

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
     * Sets the number of milliseconds until the download will timeout
     * if no connection could be established to the source
     *
     * @param connectionTimeoutMsIn the timeout in milliseconds
     */
    public void setConnectionTimeoutMillis(int connectionTimeoutMsIn) {
        this.connectionTimeoutMs = connectionTimeoutMsIn;
    }

    /**
     * Sets the number of milliseconds until the download will timeout
     * if no data could be read from the source
     *
     * @param readTimeoutMsIn the timeout in milliseconds
     */
    public void setReadTimeoutMillis(int readTimeoutMsIn) {
        this.readTimeoutMs = readTimeoutMsIn;
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
     * @param advisoryMapFile the errata advisory map csv file
     * @return a list of advisory map items
     */
    public List<ErrataAdvisoryMap> readAdvisoryMap(File advisoryMapFile) throws IOException {
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

    private File createSafeTempFile() throws IOException {
        File file = Files.createTempFile("advisoryMap", ".csv").toFile();
        file.setReadable(true, true);
        file.setWritable(true, true);
        file.setExecutable(true, true);
        return file;
    }

    /**
     * Download an advisory map from an url
     *
     * @param advisoryMapSourceUrl the advisory map url
     * @return temporary downloaded file
     */
    private File downloadErrataAdvisoryMapFile(String advisoryMapSourceUrl) throws IOException {
        URL advisoryMapURL = new URL(advisoryMapSourceUrl);
        File tempFile = createSafeTempFile();

        // Start downloading
        FileUtils.copyURLToFile(advisoryMapURL, tempFile, 15_000, 15_000);

        return tempFile;
    }

    /**
     * Downloads the advisory map
     *
     * @return the downloaded advisory map
     */
    public List<ErrataAdvisoryMap> downloadErrataAdvisoryMap() throws IOException {
        File tempFile = downloadErrataAdvisoryMapFile(ErrataAdvisoryMapManager.ADVISORY_MAP_CSV_SOURCE_URL);

        List<ErrataAdvisoryMap> advisoryMapList = readAdvisoryMap(tempFile);

        Files.delete(tempFile.toPath());
        return advisoryMapList;
    }

}
