/*
 * Copyright (c) 2009--2010 Red Hat, Inc.
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
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import javax.servlet.jsp.JspException;

/**
 * ToolbarTagDeletionTest
 */
public class ToolbarTagDeletionTest extends BaseTestToolbarTag {

    public ToolbarTagDeletionTest() {
        super();
    }

    private void setupDeletionTag(String base, String url, String acl, String type) {
        tt.setBase(base);
        tt.setDeletionUrl(url);
        tt.setDeletionAcl(acl);
        tt.setDeletionType(type);
        tt.setAclMixins(BooleanAclHandler.class.getName());
    }

    @Test
    public void testDeletionNoAcl() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
                "<div class=\"spacewalk-toolbar\"><a href=\"deletion-url\" class=\"btn btn-danger\">" +
                "<i class=\"fa fa-trash-o\" title=\"Delete User\">" +
                "</i>Delete User</a></div><h1></h1></div>";

            setupDeletionTag("h1", "deletion-url", "", "user");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testDeletionWithMissingType() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

            setupDeletionTag("h1", "deletion-url", "true_test()", "");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testCreateAclMultipleMixinsMultipleAcls() {
        try {
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
                "<div class=\"spacewalk-toolbar\"><a href=\"deletion-url\" class=\"btn btn-danger\">" +
                "<i class=\"fa fa-trash-o\" title=\"Delete User\"></i>Delete User</a>" +
                "</div><h1></h1></div>";

            setupDeletionTag("h1", "deletion-url",
                    "first_true_acl(); second_true_acl(); is_foo(foo)",
                    "user");

            tt.setAclMixins(MockOneAclHandler.class.getName() + "," +
                    MockTwoAclHandler.class.getName());

            verifyTag(output);
        }
        catch (Exception je) {
            fail(je.toString());
        }
    }

    @Test
    public void testCreateAclMultipleAclsSingleMixin() {
        try {
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
                "<div class=\"spacewalk-toolbar\"><a href=\"deletion-url\" class=\"btn btn-danger\">" +
                "<i class=\"fa fa-trash-o\" title=\"Delete User\"></i>Delete User</a>" +
                "</div><h1></h1></div>";

            setupDeletionTag("h1", "deletion-url",
                    "first_true_acl(); second_true_acl()", "user");

            tt.setAclMixins(MockOneAclHandler.class.getName());

            verifyTag(output);
        }
        catch (Exception je) {
            fail(je.toString());
        }
    }

    @Test
    public void testCreateAclValidAclInvalidMixin() {
        final String output = "<div class=\"toolbar-h1\"><div class=\"" +
                "toolbar\"></div></div>";

        setupDeletionTag("h1", "deletion-url",
                "true_test()", "user");

        tt.setAclMixins("throws.class.not.found.exception");

        assertThrows(JspException.class, () -> verifyTag(output));
    }

    @Test
    public void testDeletionAcl() {

        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
                "<div class=\"spacewalk-toolbar\"><a href=\"deletion-url\" class=\"btn btn-danger\">" +
                "<i class=\"fa fa-trash-o\" title=\"Delete User\"></i>Delete User</a>" +
                "</div><h1></h1></div>";

            setupDeletionTag("h1", "deletion-url", "true_test()", "user");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testDeletionWithMissingUrl() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

            setupDeletionTag("h1", null, "true_test()", "user");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }
}
