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

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import javax.servlet.jsp.JspException;

/**
 * ToolbarTagCreationTest
 */
public class ToolbarTagCreationTest extends BaseTestToolbarTag {

    public ToolbarTagCreationTest() {
        super();
    }

    private void setupCreationTag(String base, String url, String acl, String type) {
        tt.setBase(base);
        tt.setCreationUrl(url);
        tt.setCreationAcl(acl);
        tt.setCreationType(type);
        tt.setAclMixins(BooleanAclHandler.class.getName());
    }

    @Test
    public void testCreationNoAcl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"creation-url\" class=\"btn btn-primary\">" +
            "<i class=\"fa fa-plus\" title=\"Create User\"></i>" +
            "Create User</a></div><h1></h1></div>";

        setupCreationTag("h1", "creation-url", "", "user");

        verifyTag(output);
    }

    @Test
    public void testCreationWithMissingType() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

        setupCreationTag("h1", "creation-url", "true_test()", "");

        verifyTag(output);
    }

    @Test
    public void testCreateAclMultipleMixinsMultipleAcls() throws Exception {
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"creation-url\" class=\"btn btn-primary\">" +
            "<i class=\"fa fa-plus\" title=\"Create User\">" +
            "</i>Create User</a></div><h1></h1></div>";

        setupCreationTag("h1", "creation-url",
                         "first_true_acl(); second_true_acl(); is_foo(foo)",
                         "user");

        tt.setAclMixins(MockOneAclHandler.class.getName() + "," +
                        MockTwoAclHandler.class.getName());

        verifyTag(output);
    }

    @Test
    public void testCreateAclMultipleAclsSingleMixin() throws Exception {
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"creation-url\" class=\"btn btn-primary\">" +
            "<i class=\"fa fa-plus\" title=\"Create User\"></i>" +
            "Create User</a></div><h1></h1></div>";

        setupCreationTag("h1", "creation-url",
                         "first_true_acl(); second_true_acl()", "user");

        tt.setAclMixins(MockOneAclHandler.class.getName());

        verifyTag(output);
    }

    @Test
    public void testCreateAclValidAclInvalidMixin() {
        try {
            String output = "<div class=\"toolbar-h1\"><div class=\"" +
                "toolbar\"></div></div>";

            setupCreationTag("h1", "creation-url",
                             "true_test()", "user");

            tt.setAclMixins("throws.class.not.found.exception");

            verifyTag(output);
            fail(); //shouldn't be here
        }
        catch (JspException je) {
            // deep inside the tag, an IllegalArgumentException became
            // a JspException
            // should be here
        }
    }

    @Test
    public void testCreationAcl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"><a href=\"creation-url\" class=\"btn btn-primary\">" +
            "<i class=\"fa fa-plus\" title=\"Create User\"></i>" +
            "Create User</a></div><h1></h1></div>";

        setupCreationTag("h1", "creation-url", "true_test()", "user");

        verifyTag(output);
    }

    @Test
    public void testCreationWithMissingUrl() throws Exception {
        // setup mock objects
        String output = "<div class=\"spacewalk-toolbar-h1\">" +
            "<div class=\"spacewalk-toolbar\"></div><h1></h1></div>";

        setupCreationTag("h1", null, "true_test()", "user");

        verifyTag(output);
    }
}
