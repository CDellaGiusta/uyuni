<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://rhn.redhat.com/rhn" prefix="rhn" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://rhn.redhat.com/tags/list" prefix="rl" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>


<html>
<body>

<rhn:toolbar base="h1" icon="header-taskomatic"
             imgAlt="channels.overview.toolbar.imgAlt"
             creationUrl="/rhn/admin/ScheduleDetail.do"
             creationType="schedule"
             creationAcl="user_role(satellite_admin)"
             helpUrl="/docs/${rhn:getDocsLocale(pageContext)}/reference/admin/task-schedules.html">
    <bean:message key="schedule.edit.jsp.satschedules"/>
</rhn:toolbar>

<rl:listset name="scheduleList">
    <rhn:csrf/>
    <rhn:submitted/>


    <div class="page-summary">
           <bean:message key="schedules.jsp.introparagraph"/>
    </div>

    <br/>

    <rl:list
        emptykey="schedule.jsp.noschedules">

                <rl:decorator name="PageSizeDecorator"/>

                <rl:column sortable="true"
                           bound="false"
                           headerkey="schedule.edit.jsp.name"
                           sortattr="job_label"
                           defaultsort="asc"  >
                        <a href="/rhn/admin/ScheduleDetail.do?schid=${current.id}">${current.job_label}</a>
                </rl:column>

                <rl:column bound="false"
                           headerkey="schedule.edit.jsp.frequency" >
                    <c:if test="${current.active}">
                        <c:out value="${current.cron_expr}" />
                    </c:if>
                    <c:if test="${not current.active}">
                        <c:out value="---" />
                    </c:if>
                </rl:column>

                <rl:column sortable="true"
                           bound="false"
                           headerkey="schedule.edit.jsp.activefrom"
                           sortattr="active_from" >
                    <c:if test="${current.active}">
                        <rhn:formatDate value="${current.active_from}" />
                    </c:if>
                    <c:if test="${not current.active}">
                        <c:out value="---" />
                    </c:if>
                </rl:column>

                <rl:column bound="false"
                           headerkey="schedule.edit.jsp.bunch" >
                         <a href="/rhn/admin/BunchDetail.do?label=${current.bunch}">${current.bunch}</a>
                </rl:column>

</rl:list>
</rl:listset>

</body>
</html>
