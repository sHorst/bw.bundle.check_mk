defaults = {}

# if node.has_bundle('dehydrated') and not node.has_bundle('apache'):
#     defaults['dehydrated'] = {
#         'hooks': {
#             'deploy_cert': {
#                 'apache': ['service apache2 restart', ],
#             }
#         }
#     }
#

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'gdebi-core': {'installed': True}
        }
    }


# @metadata_reactor
# def add_dehydrated_domains(metadata):
#     if not node.has_bundle('dehydrated'):
#         raise DoNotRunAgain
#
#     domains = []
#
#     for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
#         if vhost.get('ssl', False):
#             domain_name = '{} {}'.format(vhost_name, ' '.join(vhost.get('aliases', []))).strip()
#             if domain_name not in domains:
#                 domains.append(domain_name)
#
#     return {
#         'dehydrated': {
#             'domains': domains,
#         }
#     }


@metadata_reactor
def find_hosts_to_monitor(metadata):
    sites = {}
    active_checks = {}
    host_tags = {}
    host_groups = {}
    for site, site_config in metadata.get('check_mk/sites', {}).items():
        sites[site] = {
            'folders': {},
        }
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
                    continue

                # if node.name in checked_node.partial_metadata.get('check_mk', {}).get('servers', []):
                hosts += [checked_node.name, ]

                # collect active Checks
                for name, checks in checked_node.metadata.get('check_mk/agent/active_checks', {}).items():
                    active_checks[name] = []
                    known_ids = []
                    for check in checks:
                        check_id = check.get('id', None)

                        # filter duplicates
                        if check_id is not None and check_id in known_ids:
                            continue

                        known_ids += [check_id, ]
                        active_checks[name] += [check, ]

                # collect host_tags
                for name, tags in checked_node.metadata.get('check_mk/agent/host_tags', {}).items():
                    if name in host_tags:
                        host_tags[name].setdefault('subtags', {})
                        for subtag_name, subtag in tags.get('subtags', {}).items():
                            host_tags[name]['subtags'][subtag_name] = subtag
                    else:
                        host_tags[name] = tags

                # collect host_groups
                for name, groups in checked_node.metadata.get('check_mk/agent/host_groups', {}).items():
                    host_groups[name] = groups

            sites[site]['folders'][folder] = {
                'hosts': hosts,
                'already_generated': True,
            }

    return {
        'check_mk': {
            'global_rules': {
                'active_checks': active_checks,
            },
            'host_tags': host_tags,
            'host_groups': host_groups,
            'sites': sites,
        }
    }


@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    interfaces = [metadata.get('main_interface'), ]
    interfaces += metadata.get('check_mk/additional_interfaces', [])

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
            return {}

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

    sites = {}
    # add all found server to our own list
    for site, site_config in metadata.get('check_mk/sites', {}).items():
        if not site_config.get('livestatus', False):
            continue

        sites[site] = {
            'livestatus_server': check_mk_livestatus_server,
            'livestatus_allowed_ips': list(dict.fromkeys(check_mk_livestatus_ips)),
        }

    ports = set()
    for site, site_config in metadata.get('check_mk/sites', {}).items():
        ports.add(site_config.get('livestatus_port', 6557))

    iptables_rules = {}
    # add ipTables rules
    if node.has_bundle("iptables"):
        for interface in interfaces:
            # allow snmp traps
            iptables_rules += repo.libs.iptables.accept(). \
                input(interface). \
                state_new(). \
                udp(). \
                dest_port(162)

            for server in check_mk_livestatus_server:
                for ip in server.get('ips'):
                    for port in ports:
                        iptables_rules += repo.libs.iptables.accept(). \
                            input(interface). \
                            state_new(). \
                            tcp(). \
                            source(ip). \
                            dest_port(port)

    return {
        'check_mk': {
            'sites': sites,
        },
        'iptables': iptables_rules['iptables'],
    }



