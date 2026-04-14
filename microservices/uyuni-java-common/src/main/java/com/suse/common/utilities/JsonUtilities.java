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

public class JsonUtilities {

    public static String createEmptyJson() {
        return "{}";
    }

    public static String createJson(String key, String value) {
        return addToJson("", key, value);
    }

    public static String addToJson(String json, String key, String value) {
        String body = json;
        if (body.startsWith("{")) {
            body = body.substring(1);
        }
        if (body.endsWith("}")) {
            body = body.substring(0, body.length() - 1);
        }

        if (body.isBlank()) {
            return "{\"%s\": \"%s\"}".formatted(key, value);
        }

        return "{%s, \"%s\": \"%s\"}".formatted(body, key, value);
    }
}
