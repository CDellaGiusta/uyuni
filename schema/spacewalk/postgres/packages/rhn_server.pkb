-- oracle equivalent source sha1 87bc50785a1b2a5e639cdc7371aa5c1b435adaa2
--
-- Copyright (c) 2008--2014 Red Hat, Inc.
--
-- This software is licensed to you under the GNU General Public License,
-- version 2 (GPLv2). There is NO WARRANTY for this software, express or
-- implied, including the implied warranties of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
-- along with this software; if not, see
-- http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
--
-- Red Hat trademarks are not licensed under GPLv2. No permission is
-- granted to use or replicate Red Hat trademarks that are incorporated
-- in this software or its documentation.
--
--
--
--

-- create schema rhn_server;

--update pg_setting
update pg_settings set setting = 'rhn_server,' || setting where name = 'search_path';

    create or replace function system_service_level(
    	server_id_in in numeric,
	service_level_in in varchar
    ) returns numeric as $$
    declare
    ents cursor is
      select label from rhnServerEntitlementView
      where server_id = server_id_in;

    retval numeric := 0;

    begin
         for ent in ents loop
            retval := rhn_entitlements.entitlement_grants_service (ent.label, service_level_in);
            if retval = 1 then
               return retval;
            end if;
         end loop;

         return retval;

    end$$ language plpgsql;


    create or replace function can_change_base_channel(server_id_in IN NUMERIC)
    returns numeric
    as $$
    declare
    	throwaway numeric;
    begin
    	-- the idea: if we get past this query, the server is
	-- neither sat nor proxy, so base channel is changeable

	select 1 into throwaway
	  from rhnServer S
	 where S.id = server_id_in
	   and not exists (select 1 from suseMgrServerInfo SI where SI.server_id = S.id)
	   and not exists (select 1 from rhnProxyInfo PI where PI.server_id = S.id);

        if not found then
	    return 0;
        end if;

	return 1;
    end$$ language plpgsql;

    create or replace function set_custom_value(
    	server_id_in in numeric,
	user_id_in in numeric,
	key_label_in in varchar,
	value_in in varchar
    ) returns void
    as $$
    declare
    	key_id_val numeric;
    begin
    	select CDK.id into strict key_id_val
	  from rhnCustomDataKey CDK,
	       rhnServer S
	 where S.id = server_id_in
	   and S.org_id = CDK.org_id
	   and CDK.label = key_label_in;

	begin
	    insert into rhnServerCustomDataValue (server_id, key_id, value, created_by, last_modified_by)
	    values (server_id_in, key_id_val, value_in, user_id_in, user_id_in);
	exception
	    when UNIQUE_VIOLATION
	    	then
		update rhnServerCustomDataValue
		   set value = value_in,
		       last_modified_by = user_id_in
		 where server_id = server_id_in
		   and key_id = key_id_val;
	end;

    end$$ language plpgsql;

    create or replace function bulk_set_custom_value(
    	key_label_in in varchar,
	value_in in varchar,
	set_label_in in varchar,
	set_uid_in in numeric
    )
    returns integer
    as $$
    declare
        i integer;
        server record;
    begin
        i := 0;
        for server in (
           SELECT user_id, label, element, element_two
	     FROM rhnSet
	    WHERE label = set_label_in
	      AND user_id = set_uid_in
	) loop
	    if rhn_server.system_service_level(server.element, 'management') = 1 then
	    	perform rhn_server.set_custom_value(server.element, set_uid_in, key_label_in, value_in);
            i := i + 1;
	    end if;
	end loop;
    return i;
    end$$ language plpgsql;

    create or replace function bulk_snapshot_tag(
    	org_id_in in numeric,
        tagname_in in varchar,
	set_label_in in varchar,
	set_uid_in in numeric
    ) returns void
    as $$
    declare
        server record;
    	snapshot_id numeric;
    begin
        for server in (
           SELECT user_id, label, element, element_two
	     FROM rhnSet
	    WHERE label = set_label_in
	      AND user_id = set_uid_in
	    ) loop
	    if rhn_server.system_service_level(server.element, 'management') = 1 then
	    	    select max(id) into snapshot_id
	    	    from rhnSnapshot
	    	    where server_id = server.element;

	    	    if snapshot_id is null then
		    	perform rhn_server.snapshot_server(server.element, 'tagging system:  ' || tagname_in);

			select max(id) into snapshot_id
			from rhnSnapshot
			where server_id = server.element;
		    end if;

		-- now have a snapshot_id to work with...
		begin
		    perform rhn_server.tag_snapshot(snapshot_id, org_id_in, tagname_in);
		exception
		    when UNIQUE_VIOLATION
		    	then
			-- do nothing, be forgiving...
			null;
		end;
	    end if;
	end loop;
    end$$ language plpgsql;

    create or replace function tag_delete(
    	server_id_in in numeric,
	tag_id_in in numeric
    ) returns void
    as $$
    declare
    	snapshots cursor is
		select	snapshot_id
		from	rhnSnapshotTag
		where	tag_id = tag_id_in;
	tag_id_tmp numeric;
    begin
    	select	id into tag_id_tmp
	from	rhnTag
	where	id = tag_id_in
	for update;

	delete
		from	rhnSnapshotTag
		where	server_id = server_id_in
			and tag_id = tag_id_in;
	for snapshot in snapshots loop
		return;
	end loop;
	delete
		from rhnTag
		where id = tag_id_in;
    end$$ language plpgsql;

    create or replace function tag_snapshot(
        snapshot_id_in in numeric,
	org_id_in in numeric,
	tagname_in in varchar
    ) returns void
    as $$
    begin
    	insert into rhnSnapshotTag (snapshot_id, server_id, tag_id)
	select snapshot_id_in, server_id, lookup_tag(org_id_in, tagname_in)
	from rhnSnapshot
	where id = snapshot_id_in;
    end$$ language plpgsql;

    create or replace function bulk_snapshot(
    	reason_in in varchar,
	set_label_in in varchar,
	set_uid_in in numeric
    ) returns void
    as $$
    declare
        server record;
    begin
        for server in (
           SELECT user_id, label, element, element_two
	     FROM rhnSet
	    WHERE label = set_label_in
	      AND user_id = set_uid_in
	    ) loop
	    if rhn_server.system_service_level(server.element, 'management') = 1 then
	    	perform rhn_server.snapshot_server(server.element, reason_in);
	    end if;
	end loop;
    end$$ language plpgsql;

    create or replace function snapshot_server(
    	server_id_in in numeric,
	reason_in in varchar
    ) returns void
    as $$
    declare
    	snapshot_id_v numeric;
	revisions cursor is
		select distinct
			cr.id
		from	rhnConfigRevision	cr,
			rhnConfigFileName	cfn,
			rhnConfigFile		cf,
			rhnConfigChannel	cc,
			rhnServerConfigChannel	scc
		where	1=1
			and scc.server_id = server_id_in
			and scc.config_channel_id = cc.id
			and cc.id = cf.config_channel_id
			and cf.id = cr.config_file_id
			and cr.id = cf.latest_config_revision_id
			and cf.config_file_name_id = cfn.id
			and cf.id = lookup_first_matching_cf(scc.server_id, cfn.path);
	locked integer;
    begin
    	select nextval('rhn_snapshot_id_seq') into snapshot_id_v;

	insert into rhnSnapshot (id, org_id, server_id, reason) (
		select	snapshot_id_v,
			s.org_id,
			server_id_in,
			reason_in
		from	rhnServer s
		where	s.id = server_id_in
	);
	insert into rhnSnapshotChannel (snapshot_id, channel_id) (
		select	snapshot_id_v, sc.channel_id
		from	rhnServerChannel sc
		where	sc.server_id = server_id_in
	);
	insert into rhnSnapshotServerGroup (snapshot_id, server_group_id) (
		select	snapshot_id_v, sgm.server_group_id
		from	rhnServerGroupMembers sgm
		where	sgm.server_id = server_id_in
	);
        locked := 0;
        <<iloop>>
        while true loop
            begin
                insert into rhnPackageNEVRA (id, name_id, evr_id, package_arch_id)
                select nextval('rhn_pkgnevra_id_seq'), sp.name_id, sp.evr_id, sp.package_arch_id
                from rhnServerPackage sp
                where sp.server_id = server_id_in
                        and not exists
                        (select 1
                                from rhnPackageNEVRA nevra
                                where nevra.name_id = sp.name_id
                                        and nevra.evr_id = sp.evr_id
                                        and (nevra.package_arch_id = sp.package_arch_id
                                            or (nevra.package_arch_id is null
                                                and sp.package_arch_id is null)));
                exit iloop;
            exception when unique_violation then
                if locked = 1 then
                    raise;
                else
                    lock table rhnPackageNEVRA in exclusive mode;
                    locked := 1;
                end if;
            end;
        end loop;
	insert into rhnSnapshotPackage (snapshot_id, nevra_id) (
                select distinct snapshot_id_v, nevra.id
                from    rhnServerPackage sp, rhnPackageNEVRA nevra
                where   sp.server_id = server_id_in
                        and nevra.name_id = sp.name_id
                        and nevra.evr_id = sp.evr_id
                        and (nevra.package_arch_id = sp.package_arch_id
                            or (nevra.package_arch_id is null
                                and sp.package_arch_id is null))
	);

	insert into rhnSnapshotConfigChannel ( snapshot_id, config_channel_id ) (
		select	snapshot_id_v, scc.config_channel_id
		from	rhnServerConfigChannel scc
		where	server_id = server_id_in
	);

	for revision in revisions loop
		insert into rhnSnapshotConfigRevision (
				snapshot_id, config_revision_id
			) values (
				snapshot_id_v, revision.id
			);
	end loop;
    end$$ language plpgsql;

    create or replace function remove_action(
    	server_id_in in numeric,
	action_id_in in numeric
    ) returns void
    as $$
    declare
    	-- this really wants "nulls last", but 8.1.7.3.0 sucks ass.
	-- instead, we make a local table that holds our
	-- list of ids with null prereqs.  There's surely a better way
	-- (an array instead of a table maybe?  who knows...)
	-- but I've got code to do this handy that I can look at ;)
    	chained_actions cursor is
                with recursive r(id, prerequisite) as (
			select	id, prerequisite
			from	rhnAction
			where id = action_id_in
		union all
			select	r1.id, r1.prerequisite
			from	rhnAction r1, r
			where r.id = r1.prerequisite
		)
		select * from r
		order by prerequisite desc;
	sessions cursor is
		select	s.id
		from	rhnKickstartSession s
		where	server_id_in in (s.old_server_id, s.new_server_id)
			and s.action_id = action_id_in
			and not exists (
				select	1
				from	rhnKickstartSessionState ss
				where	ss.id = s.state_id
					and ss.label in ('failed','complete')
			);
	chain_ends numeric[];
	i numeric;
	prereq numeric := 1;
    begin
	select	prerequisite
	into	prereq
	from	rhnAction
	where	id = action_id_in;

	if prereq is not null then
		perform rhn_exception.raise_exception('action_is_child');
	end if;

        chain_ends := '{}';
	i := 1;
	for action in chained_actions loop
		if action.prerequisite is null then
			chain_ends[i] := action.id;
			i := i + 1;
		else
			delete from rhnServerAction
				where server_id = server_id_in
				and action_id = action.id;
		end if;
	end loop;

	delete from rhnServerAction
		where server_id = server_id_in
		and action_id = any(chain_ends);

	for s in sessions loop
		update rhnKickstartSession
			set 	state_id = (
					select	id
					from	rhnKickstartSessionState
					where	label = 'failed'
				),
				action_id = null
			where	id = s.id;
		perform set_ks_session_history_message(s.id, 'failed', 'Kickstart cancelled due to action removal');
	end loop;
    end$$ language plpgsql;

    create or replace function check_user_access(server_id_in in numeric, user_id_in in numeric)
    returns numeric
    as $$
    declare
    	has_access numeric;
    begin
    	-- first check; if this returns no rows, then the server/user are in different orgs, and we bail
        select 1 into has_access
	  from rhnServer S,
	       web_contact wc
	 where wc.org_id = s.org_id
	   and s.id = server_id_in
	   and wc.id = user_id_in;

        if not found then
          return 0;
        end if;

	-- okay, so they're in the same org.  if we have an org admin, they get a free pass
    	if rhn_user.check_role(user_id_in, 'org_admin') = 1
	then
	    return 1;
	end if;

    	select 1 into has_access
	  from rhnServerGroupMembers SGM,
	       rhnUserServerGroupPerms USG
	 where SGM.server_group_id = USG.server_group_id
	   and SGM.server_id = server_id_in
	   and USG.user_id = user_id_in;

        if not found then
          return 0;
        end if;

	return 1;
    end$$ language plpgsql;

    create or replace function insert_into_servergroup (
		server_id_in in numeric,
		server_group_id_in in numeric
    ) returns void
    as $$
    declare
		group_type numeric;
	begin
		-- this will rowlock the servergroup we're trying to change;
		-- we probably need to lock the other one, but I think the chances
		-- of it being a real issue are very small for now...
		select	sg.group_type
		into	group_type
		from	rhnServerGroup sg
		where	sg.id = server_group_id_in
		for update of sg;

		insert into rhnServerGroupMembers(server_id, server_group_id)
		values (server_id_in, server_group_id_in);

		update rhnServerGroup
		set current_members = current_members + 1
		where id = server_group_id_in;

		if group_type is null then
			perform rhn_cache.update_perms_for_server_group(server_group_id_in);
		end if;

		return;
	end$$ language plpgsql;

	create or replace function insert_into_servergroup_maybe (
		server_id_in in numeric,
		server_group_id_in in numeric
	) returns numeric as $$
    declare
		retval numeric := 0;
		servergroups cursor is
			select	s.id	server_id,
					sg.id	server_group_id
			from	rhnServerGroup	sg,
					rhnServer		s
			where	s.id = server_id_in
				and sg.id = server_group_id_in
				and s.org_id = sg.org_id
				and not exists (
					select	1
					from	rhnServerGroupMembers sgm
					where	sgm.server_id = s.id
						and sgm.server_group_id = sg.id
				);
	begin
		for sgm in servergroups loop
			perform rhn_server.insert_into_servergroup(sgm.server_id, sgm.server_group_id);
			retval := retval + 1;
		end loop;
		return retval;
	end$$ language plpgsql;

	create or replace function insert_set_into_servergroup (
		server_group_id_in in numeric,
		user_id_in in numeric,
		set_label_in in varchar
	) returns void
        as $$
    declare
		servers cursor is
			select	st.element	id
			from	rhnSet		st
			where	st.user_id = user_id_in
				and st.label = set_label_in
				and exists (
					select	1
					from	rhnUserManagedServerGroups umsg
					where	umsg.server_group_id = server_group_id_in
						and umsg.user_id = user_id_in
					)
				and not exists (
					select	1
					from	rhnServerGroupMembers sgm
					where	sgm.server_id = st.element
						and sgm.server_group_id = server_group_id_in
				);
	begin
		for s in servers loop
			perform rhn_server.insert_into_servergroup(s.id, server_group_id_in);
		end loop;
	end$$ language plpgsql;

    create or replace function delete_from_servergroup (
    	server_id_in in numeric,
	server_group_id_in in numeric
    ) returns void
    as $$
    declare

		oid numeric;
		label varchar;
		group_type numeric;
	begin
		select	sg.group_type, sg.org_id
		into	group_type,	oid
		from	rhnServerGroupMembers	sgm,
			rhnServerGroup		sg
		where	sg.id = server_group_id_in
		and 	sg.id = sgm.server_group_id
		and 	sgm.server_id = server_id_in
		for update of sg;

		if not found then
			perform rhn_exception.raise_exception('server_not_in_group');
		end if;

		delete from rhnServerGroupMembers
		where server_group_id = server_group_id_in
		and	server_id = server_id_in;

		update rhnServerGroup
		set current_members = current_members - 1
		where id = server_group_id_in;

		-- do group_type is null first
		if group_type is null then
			perform rhn_cache.update_perms_for_server_group(server_group_id_in);
		end if;

	end$$ language plpgsql;

	create or replace function delete_set_from_servergroup (
		server_group_id_in in numeric,
		user_id_in in numeric,
		set_label_in in varchar
	) returns void
        as $$
        declare
		servergroups cursor is
			select	sgm.server_id, sgm.server_group_id
			from	rhnSet st,
					rhnServerGroupMembers sgm
			where	sgm.server_group_id = server_group_id_in
				and st.user_id = user_id_in
				and st.label = set_label_in
				and sgm.server_id = st.element
				and exists (
					select	1
					from	rhnUserManagedServerGroups usgp
					where	usgp.server_group_id = server_group_id_in
						and usgp.user_id = user_id_in
				);
	begin
		for sgm in servergroups loop
			perform rhn_server.delete_from_servergroup(sgm.server_id, server_group_id_in);
		end loop;
	end$$ language plpgsql;

	create or replace function clear_servergroup (
		server_group_id_in in numeric
	) returns void
        as $$
        declare
		servers cursor is
			select	sgm.server_id	id
			from	rhnServerGroupMembers sgm
			where	sgm.server_group_id = server_group_id_in;
	begin
		for s in servers loop
			perform rhn_server.delete_from_servergroup(s.id, server_group_id_in);
		end loop;
	end$$ language plpgsql;

	create or replace function delete_from_org_servergroups (
		server_id_in in numeric
	) returns void
        as $$
        declare
		servergroups cursor is
			select	sgm.server_group_id id
			from	rhnServerGroup sg,
					rhnServerGroupMembers sgm
			where	sgm.server_id = server_id_in
				and sgm.server_group_id = sg.id
				and sg.group_type is null;
	begin
		for sg in servergroups loop
			perform rhn_server.delete_from_servergroup(server_id_in, sg.id);
		end loop;
	end$$ language plpgsql;

	create or replace function get_ip_address (
		server_id_in in numeric
	) returns varchar as $$
        declare
		interfaces cursor is
			select	ni.name as name, na4.address as address
			from	rhnServerNetInterface ni,
			        rhnServerNetAddress4 na4
			where	server_id = server_id_in
		                and ni.id = na4.interface_id
				and na4.address != '127.0.0.1';
		addresses cursor is
			select	address ip_addr
			from	rhnServerNetInterface
      			left join rhnServerNetAddress4
      			on rhnServerNetInterface.id = rhnServerNetAddress4.interface_id
			where	server_id = server_id_in
				and address != '127.0.0.1'
				and is_primary = 'Y';
	begin
		for addr in addresses loop
			return addr.ip_addr;
		end loop;
		for iface in interfaces loop
			return iface.address;
		end loop;
		return NULL;
	end$$ language plpgsql;

    create or replace function update_needed_cache(
        server_id_in in numeric
	) returns void as $$
    begin
      delete from rhnServerNeededCache
        where server_id = server_id_in;
      insert into rhnServerNeededCache
             (server_id, errata_id, package_id, channel_id)
        (
		   with hidden_packages as materialized (
              select pid from suseServerAppStreamHiddenPackagesView where sid = server_id_in
           )
		   select distinct sp.server_id, x.errata_id, p.id, x.channel_id
           FROM (SELECT sp_sp.server_id, sp_sp.name_id,
		        sp_sp.package_arch_id, max(sp_pe.evr) AS max_evr
                   FROM rhnServerPackage sp_sp
                   join rhnPackageEvr sp_pe ON sp_pe.id = sp_sp.evr_id
                  GROUP BY sp_sp.server_id, sp_sp.name_id, sp_sp.package_arch_id) sp
           join susePackageExcludingPartOfPtf p ON p.name_id = sp.name_id
           join rhnPackageEvr pe ON pe.id = p.evr_id AND (sp.max_evr).type = (pe.evr).type AND sp.max_evr < pe.evr
           join rhnPackageUpgradeArchCompat puac
	            ON puac.package_arch_id = sp.package_arch_id
		    AND puac.package_upgrade_arch_id = p.package_arch_id
           join rhnServerChannel sc ON sc.server_id = sp.server_id
           join rhnChannelPackage cp ON cp.package_id = p.id
	            AND cp.channel_id = sc.channel_id
           left join (SELECT ep.errata_id, ce.channel_id, ep.package_id
                        FROM rhnChannelErrata ce
                        join rhnErrataPackage ep
			         ON ep.errata_id = ce.errata_id
			join rhnServerChannel sc_sc
			         ON sc_sc.channel_id = ce.channel_id
		       WHERE sc_sc.server_id = server_id_in) x
             ON x.channel_id = sc.channel_id AND x.package_id = cp.package_id
	   left join rhnErrata e on x.errata_id = e.id
          where sp.server_id = server_id_in
            and (x.errata_id IS NULL or e.advisory_status != 'retracted') -- packages which are part of a retracted errata should not be installed
            and NOT EXISTS (SELECT 1 FROM hidden_packages WHERE pid = p.id));
	end$$ language plpgsql;
-- restore the original setting
update pg_settings set setting = overlay( setting placing '' from 1 for (length('rhn_server')+1) ) where name = 'search_path';
