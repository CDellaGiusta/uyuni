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
 * ToolbarTagMiscTest
 */
public class ToolbarTagMiscTest extends BaseTestToolbarTag {

    public ToolbarTagMiscTest() {
        super();
    }

    private void setupMiscTag(String base, String url, String acl, String alt,
                              String text, String img) {
        tt.setBase(base);
        tt.setMiscUrl(url);
        tt.setMiscAcl(acl);
        tt.setMiscAlt(alt);
        tt.setMiscText(text);
        tt.setMiscImg(img);
        tt.setAclMixins(BooleanAclHandler.class.getName());
    }

    @Test
    public void testMiscNoAcl() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"misc-url\" class=\"btn btn-default\">" +
            "<img src=\"/img/foo.gif\" alt=\"ignore me\" title=\"ignore me\" />" +
            "ignore me</a></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url", "", "jsp.testMessage",
                         "jsp.testMessage", "foo.gif");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testMiscWithMissingText() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url", "true_test()",
                "alt", "", "foo.gif");

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
            "<div class=\"spacewalk-toolbar\"><a href=\"misc-url\" class=\"btn btn-default\">" +
            "<img src=\"/img/foo.gif\" alt=\"ignore me\" title=\"ignore me\" />" +
            "ignore me</a></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url",
                    "first_true_acl(); second_true_acl(); is_foo(foo)",
                    "jsp.testMessage", "jsp.testMessage", "foo.gif");

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
            "<div class=\"spacewalk-toolbar\"><a href=\"misc-url\" class=\"btn btn-default\">" +
            "<img src=\"/img/foo.gif\" alt=\"ignore me\" title=\"ignore me\" />" +
            "ignore me</a></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url",
                    "first_true_acl(); second_true_acl()", "jsp.testMessage",
                    "jsp.testMessage", "foo.gif");

            tt.setAclMixins(MockOneAclHandler.class.getName());

            verifyTag(output);
        }
        catch (Exception je) {
            fail(je.toString());
        }
    }

    @Test
    public void testCreateAclValidAclInvalidMixin() {
        String output = "<div class=\"toolbar-h1\"><div class=\"" +
                "toolbar\"></div></div>";

        setupMiscTag("h1", "misc-url",
                "true_test()", "alt", "text", "foo.gif");

        tt.setAclMixins("throws.class.not.found.exception");

        assertThrows(JspException.class, () -> verifyTag(output));
    }

    @Test
    public void testMiscAcl() {

        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"misc-url\" class=\"btn btn-default\">" +
            "<img src=\"/img/foo.gif\" alt=\"ignore me\" title=\"ignore me\" />" +
            "ignore me</a></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url", "true_test()", "jsp.testMessage",
                         "jsp.testMessage", "foo.gif");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testMiscWithMissingUrl() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

            setupMiscTag("h1", null, "true_test()", "alt", "text",
                "foo.gif");

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testMiscWithMissingImg() {
        try {
            // setup mock objects
            String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

            setupMiscTag("h1", "misc-url", "true_test()", "alt", "text",
                null);

            verifyTag(output);
        }
        catch (JspException e) {
            fail(e.toString());
        }
    }
}
