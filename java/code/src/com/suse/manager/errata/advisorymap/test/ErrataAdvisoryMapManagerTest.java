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

package com.suse.manager.errata.advisorymap.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.redhat.rhn.testing.RhnBaseTestCase;

import com.suse.manager.errata.advisorymap.ErrataAdvisoryMap;
import com.suse.manager.errata.advisorymap.ErrataAdvisoryMapFactory;
import com.suse.manager.errata.advisorymap.ErrataAdvisoryMapManager;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class ErrataAdvisoryMapManagerTest extends RhnBaseTestCase {
    private static final String TEST_ADVISORY_MAP_CSV_FILE_NAME =
            "/com/suse/manager/errata/advisorymap/test/advisory-map.csv";
    private static final long TEST_ADVISORY_MAP_RECORDS_NUM = 140938L;

    private static final boolean PRINT_STD_OUTPUT = false;
    private static final boolean PERFORM_LONG_TESTS = false;
    private long startTimeMs;

    private final ErrataAdvisoryMapManager advisoryMapManager = new ErrataAdvisoryMapManager();
    private final ErrataAdvisoryMapFactory advisoryMapFactory = new ErrataAdvisoryMapFactory();

    @SuppressWarnings("java:S106")
    private static void testPrintOut(String arg) {
        if (!PRINT_STD_OUTPUT) {
            return;
        }
        System.out.println(arg);
    }

    private void startTimeMeasure(String message) {
        testPrintOut(message);
        startTimeMs = System.currentTimeMillis();
    }

    private long stopTimeMeasure(String message) {
        long estimatedTimeMs = System.currentTimeMillis() - startTimeMs;
        testPrintOut(message + String.format("%d seconds (%d ms)", estimatedTimeMs / 1000L, estimatedTimeMs));
        return estimatedTimeMs / 1000L;
    }

    private List<ErrataAdvisoryMap> loadTestAdvisoryMap() throws IOException {
        InputStream inputStream = this.getClass().getResourceAsStream(TEST_ADVISORY_MAP_CSV_FILE_NAME);
        return advisoryMapManager.readAdvisoryMap(inputStream);
    }

    public static void createTestAdvisoryMapDatabase() throws IOException {
        InputStream inputStream = ErrataAdvisoryMapManagerTest.class
                .getResourceAsStream(TEST_ADVISORY_MAP_CSV_FILE_NAME);
        ErrataAdvisoryMapManager amm = new ErrataAdvisoryMapManager();
        List<ErrataAdvisoryMap> advisoryMapList = amm.readAdvisoryMap(inputStream);
        amm.populateErrataAdvisoryMap(advisoryMapList);
    }

    @Test
    public void loadAdvisoryMapTest() throws IOException {
        //test time: few milliseconds for 140K records
        startTimeMeasure(String.format("Loading csv file with %d records", TEST_ADVISORY_MAP_RECORDS_NUM));
        List<ErrataAdvisoryMap> advisoryMapList = loadTestAdvisoryMap();
        stopTimeMeasure("Elapsed time:");

        assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapList.size());
    }

    @Test
    public void storeNewAdvisoryMapLongTest() throws IOException {
        if (PERFORM_LONG_TESTS) {
            //test time: about 20 seconds for 140K records
            List<ErrataAdvisoryMap> advisoryMapList = loadTestAdvisoryMap();

            assertEquals(0, advisoryMapFactory.count());

            startTimeMeasure(String.format("Populating EMPTY ErrataAdvisoryMap with %d records",
                    TEST_ADVISORY_MAP_RECORDS_NUM));
            advisoryMapManager.populateErrataAdvisoryMap(advisoryMapList);
            stopTimeMeasure("Elapsed time: ");

            assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapFactory.count());
        }
    }

    @Test
    public void storeFullDuplicatedAdvisoryMapLongTest() throws IOException {
        if (PERFORM_LONG_TESTS) {
            //test time: about 40 seconds for 140K records
            List<ErrataAdvisoryMap> advisoryMapList = loadTestAdvisoryMap();
            advisoryMapManager.populateErrataAdvisoryMap(advisoryMapList);
            assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapFactory.count());

            List<ErrataAdvisoryMap> fullDuplicatedAdvisoryMapList = loadTestAdvisoryMap();
            startTimeMeasure(String.format("Populating FULL DUPLICATED ErrataAdvisoryMap with %d records",
                    TEST_ADVISORY_MAP_RECORDS_NUM));
            advisoryMapManager.populateErrataAdvisoryMap(fullDuplicatedAdvisoryMapList);
            stopTimeMeasure("Elapsed time: ");

            assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapFactory.count());
        }
    }

    @Test
    public void storeFullDifferentAdvisoryMapLongTest() throws IOException {
        if (PERFORM_LONG_TESTS) {
            //test time: about 40 seconds for 140K records
            List<ErrataAdvisoryMap> advisoryMapList = loadTestAdvisoryMap();
            advisoryMapManager.populateErrataAdvisoryMap(advisoryMapList);
            assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapFactory.count());

            List<ErrataAdvisoryMap> fullDifferentAdvisoryMapList = loadTestAdvisoryMap();
            fullDifferentAdvisoryMapList
                    .stream()
                    .forEach(r -> r.setAnnouncementId(r.getAnnouncementId() + "-DIFF"));
            startTimeMeasure(String.format("Populating FULLY DIFFERENT ErrataAdvisoryMap with %d records",
                    TEST_ADVISORY_MAP_RECORDS_NUM));
            advisoryMapManager.populateErrataAdvisoryMap(fullDifferentAdvisoryMapList);
            stopTimeMeasure("Elapsed time: ");

            assertEquals(TEST_ADVISORY_MAP_RECORDS_NUM, advisoryMapFactory.count());
        }
    }

    @Test
    public void downloadErrataAdvisoryMapFileTest() throws IOException {
        if (PERFORM_LONG_TESTS) {
            //test time: about 5 seconds for about 140K records
            startTimeMeasure("Downloading errata advisory map");
            List<ErrataAdvisoryMap> advisoryMapList = advisoryMapManager.downloadErrataAdvisoryMap();
            stopTimeMeasure("Elapsed time: ");

            testPrintOut(String.valueOf(advisoryMapList.size()));
        }
    }
}
