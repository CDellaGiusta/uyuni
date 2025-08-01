/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
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
package com.redhat.rhn.domain.action.server;

import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionChild;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.action.ActionStatus;
import com.redhat.rhn.domain.server.Server;

import com.suse.manager.maintenance.MaintenanceManager;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Class representation of the table rhnServerAction.
 */
public class ServerAction extends ActionChild implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(ServerAction.class);

    private Long resultCode;
    private Long serverId;
    private String resultMsg;
    private Date pickupTime;
    private Date completionTime;
    private Long remainingTries;

    private ActionStatus status;
    private Server server;

    private static MaintenanceManager maintenanceManager = new MaintenanceManager();

    /**
     * Getter for status
     * @return ActionStatus to get
     */
    public ActionStatus getStatus() {
        return this.status;
    }

    /**
     * Setter for status
     * @param statusIn to set
     */
    public void setStatus(ActionStatus statusIn) {
        if (Objects.equals(statusIn, ActionFactory.STATUS_FAILED) && !Objects.equals(status, statusIn)) {
            Optional.ofNullable(getParentAction()).ifPresent(pa -> {
                try {
                    pa.onFailAction(this);
                }
                catch (RuntimeException eIn) {
                    LOG.error(eIn);
                }
            });
        }
        this.status = statusIn;
    }

    public boolean isStatusQueued() {
        return status.isQueued();
    }

    /**
     * set ServerAction status to Queued
     */
    public void setStatusQueued() {
        setStatus(ActionFactory.STATUS_QUEUED);
    }

    public boolean isStatusPickedUp() {
        return status.isPickedUp();
    }

    /**
     * set ServerAction status to PickedUp
     */
    public void setStatusPickedUp() {
        setStatus(ActionFactory.STATUS_PICKED_UP);
    }

    public boolean isStatusCompleted() {
        return status.isCompleted();
    }

    /**
     * set ServerAction status to Completed
     */
    public void setStatusCompleted() {
        setStatus(ActionFactory.STATUS_COMPLETED);
    }

    public boolean isStatusFailed() {
        return status.isFailed();
    }

    /**
     * set ServerAction status to Failed
     */
    public void setStatusFailed() {
        setStatus(ActionFactory.STATUS_FAILED);
    }

    /**
     * @return if the status represents an action that is in its final state and considered done.
     * (either completed or failed)
     */
    public boolean isDone() {
        return isStatusCompleted() || isStatusFailed();
    }

    /**
     * Getter for resultCode
     * @return Long to get
    */
    public Long getResultCode() {
        return this.resultCode;
    }

    /**
     * Setter for resultCode
     * @param resultCodeIn to set
    */
    public void setResultCode(Long resultCodeIn) {
        this.resultCode = resultCodeIn;
    }

    /**
     * Getter for resultMsg
     * @return String to get
    */
    public String getResultMsg() {
        return this.resultMsg;
    }

    /**
     * Setter for resultMsg
     * @param resultMsgIn to set
    */
    public void setResultMsg(String resultMsgIn) {
        this.resultMsg = resultMsgIn;
    }

    /**
     * Getter for pickupTime
     * @return Date to get
    */
    public Date getPickupTime() {
        return this.pickupTime;
    }

    /**
     * Setter for pickupTime
     * @param pickupTimeIn to set
    */
    public void setPickupTime(Date pickupTimeIn) {
        this.pickupTime = pickupTimeIn;
    }

    /**
     * Getter for completionTime
     * @return Date to get
    */
    public Date getCompletionTime() {
        return this.completionTime;
    }

    /**
     * Setter for completionTime
     * @param completionTimeIn to set
    */
    public void setCompletionTime(Date completionTimeIn) {
        this.completionTime = completionTimeIn;
    }

    /**
     * Getter for remainingTries
     * @return Long to get
    */
    public Long getRemainingTries() {
        return this.remainingTries;
    }

    /**
     * Setter for remainingTries
     * @param remainingTriesIn to set
    */
    public void setRemainingTries(Long remainingTriesIn) {
        this.remainingTries = remainingTriesIn;
    }

    /**
     * Gets the Server associated with this ServerAction record
     * @return Returns the server.
     */
    public Server getServer() {
        return server;
    }

    /**
     * Sets the Server associated with this ServerAction record
     * Checks if the Action scheduled date fits in Maintenance windows, if system has any Maintenance schedule assigned.
     *
     * @param serverIn The server to set.
     */
    public void setServerWithCheck(Server serverIn) {
        Action parentAction = getParentAction();
        if (parentAction != null) {
            maintenanceManager.canActionBeScheduled(Set.of(serverIn.getId()), parentAction);
        }
        setServer(serverIn);
    }

    private void setServer(Server serverIn) {
        this.server = serverIn;
        this.setServerId(serverIn.getId());
    }

    /**
     *
     * Sets the parent Action associated with this ServerAction record.
     * Checks if the Action scheduled date fits in Maintenance windows, if system has any Maintenance schedule assigned.
     *
     * @param parentActionIn The parentAction to set.
     */
    public void setParentActionWithCheck(Action parentActionIn) {
        if (serverId != null) {
            maintenanceManager.canActionBeScheduled(Set.of(serverId), parentActionIn);
        }

        setParentAction(parentActionIn);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object otherObject) {
        if (!(otherObject instanceof ServerAction other)) {
            return false;
        }
        // HACK: if object are fully populated, only look at IDs to avoid costly
        // compare hash operations
        Action thisAction = getParentAction();
        Action otherAction = other.getParentAction();
        Server thisServer = getServer();
        Server otherServer = other.getServer();

        if (thisAction != null && otherAction != null && thisServer != null &&
                otherServer != null) {
            return new EqualsBuilder()
                    .append(thisAction.getId(), otherAction.getId())
                    .append(thisServer.getId(), otherServer.getId())
                    .isEquals();
        }

        return new EqualsBuilder()
                .append(thisAction, otherAction)
                .append(thisServer, otherServer)
                .isEquals();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        // HACK: if object is fully populated, only look at IDs to avoid costly
        // hash operations
        Action thisAction = getParentAction();
        Server thisServer = getServer();

        if (thisAction != null && thisServer != null) {
            return new HashCodeBuilder()
                    .append(thisAction.getId())
                    .append(thisServer.getId())
                    .toHashCode();
        }

        return new HashCodeBuilder()
            .append(thisAction)
            .append(thisServer)
            .toHashCode();
    }

    /**
     * get the server ID
     * @return the server id
     */
    public Long getServerId() {
        return serverId;
    }

    /**
     * Set the server id
     * @param serverIdIn the serverid
     */
    public void setServerId(Long serverIdIn) {
        this.serverId = serverIdIn;
    }

    /**
     * Set this server action to FAILED.
     * @param message the message to set in the server action
     */
    public void fail(String message) {
        this.fail(-1L, message);
    }

    /**
     * Set this server action to FAILED.
     * @param resultCodeIn the result code set in the server action
     * @param message the message to set in the server action
     */
    public void fail(long resultCodeIn, String message) {
        this.fail(resultCodeIn, message, new Date());
    }

    /**
     * Set this server action to FAILED.
     * @param resultCodeIn the result code set in the server action
     * @param message the message to set in the server action
     * @param completionTimeIn the completionTime to set in the server action
     */
    public void fail(long resultCodeIn, String message, Date completionTimeIn) {
        this.setCompletionTime(completionTimeIn);
        this.setResultCode(resultCodeIn);
        this.setStatusFailed();
        this.setResultMsg(message);
    }

    /**
     * @return Returns TRUE if this server action status is FAILED. Otherwise, returns FALSE.
     */
    public boolean isFailed() {
        return  ActionFactory.STATUS_FAILED.equals(status);
    }

    @Override
    public String toString() {
        return "ServerAction{" +
                "serverId=" + serverId +
                ", actionId=" + Optional.ofNullable(getParentAction()).map(a -> a.getId().toString()).orElse("?") +
                ", resultCode=" + resultCode +
                ", status=" + status +
                '}';
    }
}
