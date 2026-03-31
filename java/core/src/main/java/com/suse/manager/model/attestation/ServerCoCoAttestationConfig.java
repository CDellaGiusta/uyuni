/*
 * Copyright (c) 2024--2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */
package com.suse.manager.model.attestation;

import com.redhat.rhn.domain.server.Server;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.hibernate.annotations.Type;

import java.io.Serializable;
import java.util.Map;
import java.util.TreeMap;

import io.hypersistence.utils.hibernate.type.json.JsonType;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

@Entity
@Table(name = "suseServerCoCoAttestationConfig")
public class ServerCoCoAttestationConfig implements Serializable  {
    private Long id;
    private Server server;
    private boolean enabled;
    private CoCoEnvironmentType environmentType;
    private boolean attestOnBoot;

    private CoCoAttestationStatus status;
    private Map<String, Object> inData = new TreeMap<>();
    private Map<String, Object> outData = new TreeMap<>();

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    public CoCoAttestationStatus getStatus() {
        return status;
    }

    @Type(JsonType.class)
    @Column(columnDefinition = "jsonb", name = "in_data")
    public Map<String, Object> getInData() {
        return inData;
    }

    @Type(JsonType.class)
    @Column(columnDefinition = "jsonb", name = "out_data")
    public Map<String, Object> getOutData() {
        return outData;
    }

    /**
     * @param statusIn the status to set
     */
    public void setStatus(CoCoAttestationStatus statusIn) {
        status = statusIn;
    }

    /**
     * @param inDataIn the input data to set
     */
    public void setInData(Map<String, Object> inDataIn) {
        inData = inDataIn;
    }

    /**
     * @param outDataIn the output data to set
     */
    public void setOutData(Map<String, Object> outDataIn) {
        outData = outDataIn;
    }

//    //
//    ALTER TABLE suseServerCoCoAttestationConfig
//    ADD COLUMN status character varying(32) COLLATE pg_catalog."default" NOT NULL;
//
//    ALTER TABLE suseServerCoCoAttestationConfig
//    ADD COLUMN in_data jsonb NOT NULL;
//
//    ALTER TABLE suseServerCoCoAttestationConfig
//    ADD COLUMN out_data jsonb NOT NULL;
//
//    ALTER TABLE suseServerCoCoAttestationConfig
//    ADD CONSTRAINT suse_srvcocoatt_conf_st_ck CHECK (status::text = ANY (ARRAY['PENDING'::character varying, 'SUCCEEDED'::character varying, 'FAILED'::character varying]::text[]))



    // Default empty constructor for hibernate
    protected ServerCoCoAttestationConfig() {
        this(false, null);
    }

    /**
     * Constructor
     *
     * @param enabledIn if attestation is enabled for this server
     * @param serverIn the server
     */
    public ServerCoCoAttestationConfig(boolean enabledIn, Server serverIn) {
        enabled = enabledIn;
        server = serverIn;
        environmentType = CoCoEnvironmentType.NONE;
        attestOnBoot = false;
    }

    /**
     * @return return the ID
     */
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "suse_srvcocoatt_cnf_seq")
    @SequenceGenerator(
            name = "suse_srvcocoatt_cnf_seq", sequenceName = "suse_srvcocoatt_cnf_id_seq", allocationSize = 1
    )
    public Long getId() {
        return id;
    }

    /**
     * @return return the server
     */
    @ManyToOne
    @JoinColumn(name = "server_id")
    public Server getServer() {
        return server;
    }

    /**
     * @return return if enabled
     */
    @Column(name = "enabled")
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return return the selected environment type
     */
    @Column(name = "env_type")
    @Convert(converter = CoCoEnvironmentTypeConverter.class)
    public CoCoEnvironmentType getEnvironmentType() {
        return environmentType;
    }

    @Column(name = "attest_on_boot")
    public boolean isAttestOnBoot() {
        return attestOnBoot;
    }

    /**
     * Use setServer() instead
     * @param idIn set the id
     */
    protected void setId(Long idIn) {
        id = idIn;
    }

    /**
     * @param serverIn the server object
     */
    public void setServer(Server serverIn) {
        server = serverIn;
    }

    /**
     * @param enabledIn set is enabled
     */
    public void setEnabled(boolean enabledIn) {
        enabled = enabledIn;
    }

    /**
     * @param environmentTypeIn set the environment type
     */
    public void setEnvironmentType(CoCoEnvironmentType environmentTypeIn) {
        environmentType = environmentTypeIn;
    }

    public void setAttestOnBoot(boolean attestOnBootIn) {
        this.attestOnBoot = attestOnBootIn;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ServerCoCoAttestationConfig that = (ServerCoCoAttestationConfig) o;
        return new EqualsBuilder()
                .append(outData, that.outData)
                .append(inData, that.inData)
                .append(status, that.status)
                .append(enabled, that.enabled)
                .append(environmentType, that.environmentType)
                .append(server, that.server)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(server)
                .append(enabled)
                .append(environmentType)
                .append(outData)
                .append(inData)
                .append(status)
                .toHashCode();
    }

    @Override
    public String toString() {
        return "ServerCoCoAttestationConfig{" +
                "server=" + server +
                ", enabled=" + enabled +
                ", environmentType=" + environmentType +
                ", status=" + status +
                '}';
    }
}
