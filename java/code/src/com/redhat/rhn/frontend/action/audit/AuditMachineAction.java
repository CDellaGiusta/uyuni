/*
 * Copyright (c) 2009--2015 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.audit;

import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.util.StringUtil;
import com.redhat.rhn.frontend.dto.AuditReviewDto;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.taglibs.list.ListTagHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.audit.AuditManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;
import org.apache.struts.action.ActionMessages;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AuditMachineAction
 */
public class AuditMachineAction extends RhnAction implements Listable<AuditReviewDto> {

    private static Logger log = LogManager.getLogger(AuditMachineAction.class);

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping,
                                 ActionForm form,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        ActionMessages amsgs;
        Enumeration<String> paramNames;
        ListHelper helper = new ListHelper(this, request);
        Long start, end;
        Map<String, Object> forwardParams = makeParamMap(request);
        RequestContext requestContext = new RequestContext(request);
        String str, reviewed, machine, username;

        helper.execute();

        request.setAttribute(ListTagHelper.PARENT_URL, request.getRequestURI());

        machine = request.getParameter("machine");
        reviewed = request.getParameter("reviewed");

        // is this a review?
        if (reviewed != null && !reviewed.isEmpty()) {
            start = Long.parseLong(request.getParameter("startMilli"));
            end = Long.parseLong(request.getParameter("endMilli"));
            username = requestContext.getCurrentUser().getLogin();

            if (log.isDebugEnabled()) {
                log.debug("reviewed: {}, {}, {}, {}", StringUtil.sanitizeLogInput(machine), start, end, username);
            }

            try {
                AuditManager.markReviewed(machine, start, end, username);

                forwardParams.put("machine", machine);

                return getStrutsDelegate().forwardParams(
                    mapping.findForward("success"),
                    forwardParams); // to send "machine" over
            }
            catch (IOException ioex) {
                log.warn("failed to write review!", ioex);
                amsgs = new ActionMessages();
                amsgs.add(ActionMessages.GLOBAL_MESSAGE,
                    new ActionMessage("Failed to save review!", false));
                addMessages(request, amsgs);
            }
        }

        // set up parameters to forward
        paramNames = request.getParameterNames();

        while (paramNames.hasMoreElements()) {
            str = paramNames.nextElement();
            forwardParams.put(str, request.getParameter(str));
        }

        request.setAttribute("machine", machine);

        return getStrutsDelegate().forwardParams(
            mapping.findForward(RhnHelper.DEFAULT_FORWARD),
            forwardParams);
    }

    /** {@inheritDoc} */
    @Override
    public DataResult<AuditReviewDto> getResult(RequestContext context) {
        return AuditManager.getMachineReviewSections(
            context.getParam("machine", false));
    }
}
