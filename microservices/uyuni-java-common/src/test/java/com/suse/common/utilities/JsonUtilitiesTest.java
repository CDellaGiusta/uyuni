/*
 * Copyright (c) 2026 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */

package com.suse.common.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class JsonUtilitiesTest {
    @Test
    @DisplayName("correctly creates empty json")
    void testCreateEmptyJson() {
        assertEquals("{}", JsonUtilities.createEmptyJson());
    }

    @Test
    @DisplayName("correctly creates simple json")
    void testCreateJson() {
        assertEquals("{\"newKey\": \"newVal\"}", JsonUtilities.createJson("newKey", "newVal"));
    }

    @Test
    @DisplayName("correctly adds json on top of empty json")
    void testAddToJsonWithExistingEmptyJson() {

        assertEquals("{\"newKey\": \"newVal\"}",
                JsonUtilities.addToJson("  ", "newKey", "newVal"));

        assertEquals("{\"newKey\": \"newVal\"}",
                JsonUtilities.addToJson("{}", "newKey", "newVal"));

        assertEquals("{\"newKey\": \"newVal\"}",
                JsonUtilities.addToJson("{   }", "newKey", "newVal"));
    }

    @Test
    @DisplayName("correctly adds json on top of existing json")
    void testAddToJsonWithExistingJson() {
        assertEquals("{\"exKey\": \"exVal\", \"exKey2\": exVal2, \"newKey\": \"newVal\"}",
                JsonUtilities.addToJson("{\"exKey\": \"exVal\", \"exKey2\": exVal2}", "newKey", "newVal"));
    }
}
