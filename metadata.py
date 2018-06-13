
@metadata_processor
def add_dehydrated_hook(metadata):
    if node.has_bundle('dehydrated'):
        metadata.setdefault('dehydrated', {})\
            .setdefault('hooks', {})\
            .setdefault('deploy_cert', {})

        metadata['dehydrated']['hooks']['deploy_cert']['apache'] = ['service apache2 restart', ]

    return metadata, DONE


@metadata_processor
def add_dehydrated_domains(metadata):
    if node.has_bundle('dehydrated'):
        metadata.setdefault('dehydrated', {}).setdefault('domains', [])
        for vhost_name, vhost in metadata.get('apache', {}).get('vhosts', {}).items():
            if vhost.get('ssl', False):
                metadata['dehydrated']['domains'].append('{} {}'
                                                         .format(vhost_name, ' '.join(vhost.get('aliases', [])))
                                                         .strip())

    return metadata, DONE


@metadata_processor
def find_hosts_to_monitor(metadata):
    for site, site_config in metadata.get('check_mk', {}).get('sites', {}).items():
        for folder, folder_config in site_config.get('folders').items():
            if not folder_config.get('generated', False):
                continue

            if folder_config.get('already_generated', False):
                continue

            group = folder_config.get('group', None)
            bundle = folder_config.get('bundle', None)
            include_self = folder_config.get('include_self', False)

            hosts = []
            for checked_node in sorted(repo.nodes, key=lambda x: x.name):
                if not checked_node.has_bundle('check_mk_agent'):
                    continue

                if not include_self and checked_node.name == node.name:
                    continue

                if group and not checked_node.in_group(group):
                    continue

                if bundle and not checked_node.has_bundle(bundle):
                    continue

                if checked_node.partial_metadata == {}:
                    return metadata, RUN_ME_AGAIN

                # if node.name in checked_node.partial_metadata.get('check_mk', {}).get('servers', []):
                hosts += [checked_node.name, ]

            metadata['check_mk']['sites'][site]['folders'][folder]['hosts'] = hosts
            metadata['check_mk']['sites'][site]['folders'][folder]['already_generated'] = True

    return metadata, DONE


@metadata_processor
def add_iptables_rules(metadata):
    interfaces = [metadata.get('main_interface'), ]
    interfaces += metadata['check_mk'].get('additional_interfaces', [])

    # find server for livestatus
    check_mk_livestatus_server = []
    check_mk_livestatus_ips = []
    for tnode in repo.nodes:
        # do not add ourself
        if tnode.name == node.name:
            continue

        if not tnode.has_bundle('check_mk'):
            continue

        if tnode.partial_metadata == {}:
            return metadata, RUN_ME_AGAIN

        # find ips for server
        check_mk_server_ips = []
        for interface, interface_config in tnode.partial_metadata.get('interfaces', {}).items():
            if interface not in interfaces and interface != tnode.partial_metadata.get('main_interface'):
                continue

            check_mk_server_ips += interface_config.get('ip_addresses', [])
            check_mk_server_ips += interface_config.get('ipv6_addresses', [])

        for site, site_config in tnode.partial_metadata.get('check_mk', {}).get('sites', {}).items():
            if not site_config.get('livestatus', False):
                continue

            check_mk_livestatus_server += [{
                'name': tnode.name,
                'hostname': tnode.hostname,
                'site': site,
                'ips': list(dict.fromkeys(check_mk_server_ips)),
                'port': site_config.get('livestatus_port', 6557),
            }]

            check_mk_livestatus_ips += check_mk_server_ips

    # add all found server to our own list
    for site, site_config in metadata.get('check_mk', {}).get('sites', {}).items():
        if not site_config.get('livestatus', False):
            continue

        metadata['check_mk']['sites'][site]['livestatus_server'] = check_mk_livestatus_server
        metadata['check_mk']['sites'][site]['livestatus_allowed_ips'] = list(dict.fromkeys(check_mk_livestatus_ips))

    ports = set()
    for site, site_config in metadata['check_mk'].get('sites', {}).items():
        ports.add(site_config.get('livestatus_port', 6557))

    # add ipTables rules
    if node.has_bundle("iptables"):
        for interface in interfaces:
            # allow snmp traps
            metadata += repo.libs.iptables.accept(). \
                input(interface). \
                state_new(). \
                udp(). \
                dest_port(162)

            for server in check_mk_livestatus_server:
                for ip in server.get('ips'):
                    for port in ports:
                        metadata += repo.libs.iptables.accept(). \
                            input(interface). \
                            state_new(). \
                            tcp(). \
                            source(ip). \
                            dest_port(port)

    return metadata, DONE


