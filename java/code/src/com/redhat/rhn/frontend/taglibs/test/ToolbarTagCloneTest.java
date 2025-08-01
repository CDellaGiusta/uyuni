/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
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
package com.redhat.rhn.frontend.taglibs.test;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import javax.servlet.jsp.JspException;

/**
 * ToolbarTagCloneTest
 */
public class ToolbarTagCloneTest extends BaseTestToolbarTag {

    public ToolbarTagCloneTest() {
        super();
    }

    private void setupCloneTag(String base, String url, String acl, String type) {
        tt.setBase(base);
        tt.setCloneUrl(url);
        tt.setCloneAcl(acl);
        tt.setCloneType(type);
        tt.setAclMixins(BooleanAclHandler.class.getName());
    }

    @Test
    public void testCloneNoAcl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"Clone-url\" class=\"btn btn-default\">" +
            "<i class=\"fa fa-files-o\" title=\"Clone Autoinstallation\"></i>" +
            "Clone Autoinstallation</a></div><h1></h1></div>";


        setupCloneTag("h1", "Clone-url", "", "kickstart");

        verifyTag(output);
    }

    @Test
    public void testCloneWithMissingType() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

        setupCloneTag("h1", "Clone-url", "true_test()", "");

        verifyTag(output);
    }

    @Test
    public void testCreateAclMultipleMixinsMultipleAcls() throws Exception {
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"Clone-url\" class=\"btn btn-default\">" +
            "<i class=\"fa fa-files-o\" title=\"Clone Autoinstallation\"></i>" +
            "Clone Autoinstallation</a></div><h1></h1></div>";

        setupCloneTag("h1", "Clone-url",
                         "first_true_acl(); second_true_acl(); is_foo(foo)",
                         "kickstart");

        tt.setAclMixins(MockOneAclHandler.class.getName() + "," +
                        MockTwoAclHandler.class.getName());

        verifyTag(output);
    }

    @Test
    public void testCreateAclMultipleAclsSingleMixin() throws Exception {
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"Clone-url\" class=\"btn btn-default\">" +
            "<i class=\"fa fa-files-o\" title=\"Clone Autoinstallation\">" +
            "</i>Clone Autoinstallation</a></div><h1></h1></div>";

        setupCloneTag("h1", "Clone-url",
                         "first_true_acl(); second_true_acl()", "kickstart");

        tt.setAclMixins(MockOneAclHandler.class.getName());

        verifyTag(output);
    }

    @Test
    public void testCreateAclValidAclInvalidMixin() {
        final String output = "<div class=\"toolbar-h1\"><div class=\"" +
                "toolbar\"></div></div>";

        setupCloneTag("h1", "Clone-url",
                "true_test()", "kickstart");

        tt.setAclMixins("throws.class.not.found.exception");

        // deep inside the tag, an IllegalArgumentException became
        // a JspException
        assertThrows(JspException.class, () -> verifyTag(output));
    }

    @Test
    public void testCloneAcl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"Clone-url\" class=\"btn btn-default\">" +
            "<i class=\"fa fa-files-o\" title=\"Clone Autoinstallation\"></i>" +
            "Clone Autoinstallation</a></div><h1></h1></div>";

        setupCloneTag("h1", "Clone-url", "true_test()", "kickstart");

        verifyTag(output);
    }

    @Test
    public void testCloneWithMissingUrl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

        setupCloneTag("h1", null, "true_test()", "kickstart");

        verifyTag(output);
    }
}

