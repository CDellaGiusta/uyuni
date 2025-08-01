/*
 * Copyright (c) 2011--2014 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.tasko;

import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.taskomatic.TaskomaticApiException;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * SatSchedulesAction
 */
public class SatSchedulesAction extends RhnAction implements Listable<Map<String, Object>> {

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping,
                                 ActionForm formIn,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        ListHelper helper = new ListHelper(this, request);
        helper.execute();
        return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
    }

    /** {@inheritDoc} */
    @Override
    public List<Map<String, Object>> getResult(RequestContext contextIn) {
        User user =  contextIn.getCurrentUser();
        try {
            List<Map<String, Object>> allSchedules = new TaskomaticApi().findAllSatSchedules(user);
            return allSchedules.stream()
                    .filter(s -> !s.get("job_label").equals("payg-dimension-computation-default"))
                    .filter(s -> s.get("cron_expr") != null)
                    .map(s -> {
                        Date till = (Date) s.get("active_till");
                        s.put("active", (till == null || till.after(new Date())));
                        return s;
                    })
                    .collect(Collectors.toList());
        }
        catch (TaskomaticApiException e) {
            createErrorMessage(contextIn.getRequest(),
                    "repos.jsp.message.taskomaticdown", null);
            return new ArrayList<>();
        }
    }
}
