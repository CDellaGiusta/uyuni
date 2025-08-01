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
import com.redhat.rhn.frontend.dto.AuditMachineDto;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.taglibs.list.ListTagHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.audit.AuditManager;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AuditAction
 */
public class AuditAction extends RhnAction implements Listable<AuditMachineDto> {

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping,
                                 ActionForm form,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        Enumeration<String> paramNames;
        ListHelper helper = new ListHelper(this, request);
        Map<String, Object> forwardParams = makeParamMap(request);
        String str;

        helper.execute();

        request.setAttribute(ListTagHelper.PARENT_URL, request.getRequestURI());

        // set up parameters to forward
        paramNames = request.getParameterNames();

        while (paramNames.hasMoreElements()) {
            str = paramNames.nextElement();
            forwardParams.put(str, request.getParameter(str));
        }

        return getStrutsDelegate().forwardParams(
            mapping.findForward(RhnHelper.DEFAULT_FORWARD),
            forwardParams);
    }

    /** {@inheritDoc} */
    @Override
    public DataResult<AuditMachineDto> getResult(RequestContext context) {
        return AuditManager.getMachines();
    }
}
