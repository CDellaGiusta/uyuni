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
package com.redhat.rhn.frontend.action.multiorg;

import com.redhat.rhn.common.security.PermissionException;
import com.redhat.rhn.common.validator.ValidatorError;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.struts.RhnValidationHelper;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;
import org.apache.struts.action.ActionMessages;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OrgDetailsAction extends RhnAction - Class representation of the table
 * web_customer
 */
public class OrgConfigAction extends RhnAction {
    private static final String SCAP_RETENTION_PERIOD = "scap_retention_period";
    private static final String SCAP_RETENTION_SET = "scap_retention_set";


    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm formIn,
            HttpServletRequest request, HttpServletResponse response) {
        RequestContext ctx = new RequestContext(request);
        Org org = ctx.getCurrentUser().getOrg();
        if (!ctx.getCurrentUser().hasRole(RoleFactory.ORG_ADMIN)) {
            throw new PermissionException("Organization Administrator role is required.");
        }
        request.setAttribute(RequestContext.ORG, org);
        request.setAttribute("edit_disabled", !org.getOrgAdminMgmt().isEnabled());
        if (org.getOrgAdminMgmt().isEnabled()) {
            return process(mapping, request, ctx, org);
        }
        else {
            return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
        }
    }

    protected ActionForward process(ActionMapping mapping, HttpServletRequest request,
            RequestContext ctx, Org org) {
        if (ctx.isSubmitted()) {
            org.getOrgConfig().setStagingContentEnabled(request.
                    getParameter("staging_content_enabled") != null);
            org.getOrgConfig().setClmSyncPatches(request.
                    getParameter("clm_sync_patches_enabled") != null);
            org.getOrgConfig().setErrataEmailsEnabled(request.
                    getParameter("errata_emails_enabled") != null);

            org.getOrgConfig().setScapfileUploadEnabled(request.
                    getParameter("scapfile_upload_enabled") != null);

            Long newScapRetentionPeriod = null;
            try {
                newScapRetentionPeriod = Long.parseLong(
                           request.getParameter(SCAP_RETENTION_PERIOD));

                if (newScapRetentionPeriod < 0) {
                    throw new IllegalArgumentException();
                }
            }
            catch (IllegalArgumentException ex) {
                ValidatorError error = new ValidatorError("orgsizelimit.invalid");
                getStrutsDelegate().saveMessages(request,
                    RhnValidationHelper.validatorErrorToActionErrors(error));

                return getStrutsDelegate().forwardParam(mapping.findForward("error"),
                           RequestContext.ORG_ID, org.getId().toString());
            }
            if (StringUtils.isNotEmpty(request.getParameter(SCAP_RETENTION_PERIOD))) {
                org.getOrgConfig().setScapRetentionPeriodDays(newScapRetentionPeriod);
            }
            if (!getOptionScapRetentionPeriodSet(request)) {
                org.getOrgConfig().setScapRetentionPeriodDays(null);
            }

            ActionMessages msg = new ActionMessages();
            msg.add(ActionMessages.GLOBAL_MESSAGE,
                    new ActionMessage("message.org_name_updated",
                    StringEscapeUtils.escapeHtml4(org.getName())));
            getStrutsDelegate().saveMessages(request, msg);
            return getStrutsDelegate().forwardParam(mapping.findForward("success"),
                    RequestContext.ORG_ID,
                    org.getId().toString());
        }
        return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
    }

    private boolean getOptionScapRetentionPeriodSet(HttpServletRequest request) {
        String strRetentionSet = request.getParameter(SCAP_RETENTION_SET);
        return "on".equals(strRetentionSet);
    }
}
