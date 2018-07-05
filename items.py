from passlib.hash import md5_crypt
from bundlewrap.utils.dicts import merge_dict


def sort_by_prio(x):
    if isinstance(x[1], list):
        return x[0]
    else:
        return '{}_{}'.format(x[1].get('prio', 10), x[0])


def format_hosts(hosts):
    if isinstance(hosts, list):
        return '[' + ", ".join(map(lambda x: "'{}'".format(x), hosts)) + ']'

    return hosts


def format_services(services):
    if isinstance(services, list):
        return '[' + ", ".join(map(lambda x: "'{}'".format(x), services)) + ']'

    return services


def dict_to_string_python_2(format_dict):
    output = []
    for dict_key, dict_value in format_dict.items():
        if isinstance(dict_value, str):
            output += ["'{}': u'{}'".format(dict_key, dict_value), ]
        elif isinstance(dict_value, dict):
            output += ["'{}': {}".format(dict_key, dict_to_string_python_2(dict_value)), ]
        else:
            output += ["'{}': {}".format(dict_key, dict_value), ]

    return "{{{}}}".format(', '.join(output))


def format_rule(rule_config):
    check_mk_variables = ['ALL_HOSTS']

    if isinstance(rule_config, tuple) or isinstance(rule_config, list):
        config = rule_config[0]
        if isinstance(rule_config[0], str):
            config = "'{}'".format(rule_config[0])

        output = '('

        if len(rule_config) >= 1:
            output += "{}".format(
                config,
            )

        if len(rule_config) >= 2:
            output += ", {}".format(
                "['{}', ]".format("', '".join(rule_config[1])) if len(rule_config[1]) else '[]',
            )

        if len(rule_config) >= 3:
            output += ", {}".format(
                "'{}'".format(rule_config[2]) if rule_config[2] not in check_mk_variables else rule_config[2],
            )

        if len(rule_config) >= 4:
            output += ', {}'.format(
                dict_to_string_python_2(rule_config[3]),
            )

        if len(rule_config) >= 5:
            raise BundleError(_(
                "Config Rule has to many values {item} in bundle '{bundle}'"
            ).format(
                file=self.node.name,
                bundle=bundle.name,
                item=item_id,
            ))

        output += ')'

        return output
    else:
        return rule_config


def generate_rules(config_rules):
    output_rules = []

    for rule, rule_config in sorted(config_rules.items(), key=sort_by_prio):
        if isinstance(rule_config, list):
            output_rules += [
                'if {} == None:'.format(rule),
                '  {} = []'.format(rule),
                '',
                '{} = ['.format(rule)
            ]
            output_rules += map(lambda x: "  {},".format(format_rule(x)), rule_config)
            output_rules += [
                '] + {}'.format(rule),
                ''
            ]
        elif isinstance(rule_config, dict):
            for subrule, subrule_config in sorted(rule_config.items(), key=sort_by_prio):
                output_rules += [
                    '{}.setdefault(\'{}\', [])'.format(rule, subrule),
                    '{}[\'{}\'] = ['.format(rule, subrule),
                ]
                output_rules += map(lambda x: "  {},".format(format_rule(x)), subrule_config)
                output_rules += [
                    '] + {}[\'{}\']'.format(rule, subrule),
                    ''
                ]

    return output_rules


check_mk_config = node.metadata.get('check_mk', {})

if check_mk_config.get('beta', False):
    CHECK_MK_VERSION = '1.5.0b3'
    CHECK_MK_DEB_FILE = 'check-mk-raw-{}_0.stretch_amd64.deb'.format(CHECK_MK_VERSION)
    CHECK_MK_DEB_FILE_SHA256 = '3c56922dbd7e95b451f758782b37880649d0adc0ddad43918badf555562b5e27'
else:
    CHECK_MK_VERSION = '1.4.0p31'
    CHECK_MK_DEB_FILE = 'check-mk-raw-{}_0.stretch_amd64.deb'.format(CHECK_MK_VERSION)
    CHECK_MK_DEB_FILE_SHA256 = 'cbbd46be8b486c12f74e4368a1d8e608864aaa105bf85c165e7604fcba7668f0'

pkg_apt = {
    'gdebi-core': {
        'installed': True,
    }
}

files = {}
directories = {}
downloads = {
    '/opt/{}'.format(CHECK_MK_DEB_FILE): {
        'url': 'https://mathias-kettner.de/support/{}/{}'.format(CHECK_MK_VERSION, CHECK_MK_DEB_FILE),
        'sha256': CHECK_MK_DEB_FILE_SHA256,
        'needs': [
            'pkg_apt:gdebi-core',
        ],
    }
}

actions = {
    'install_check_mk': {
        'command': 'gdebi -n /opt/{}'.format(CHECK_MK_DEB_FILE),
        'unless': 'omd version | grep {}'.format(CHECK_MK_VERSION),
        'needs': [
            'download:/opt/{}'.format(CHECK_MK_DEB_FILE),
            'pkg_apt:gdebi-core',
        ],
    }
}


for site, site_config in check_mk_config.get('sites', {}).items():
    admin_email = site_config.get('admin_email', '')
    site_folder = '/omd/sites/{site}'.format(site=site)
    site_url = '{url}/{site}/'.format(url=site_config.get('url', node.hostname), site=site)

    site_host_tags = site_config.get('host_tags', {})
    if isinstance(site_host_tags, list):
        tmp = site_host_tags
        site_host_tags = {}

        for name, description, subtags_list in tmp:
            subtags = {}
            for subtag_name, subtag_descr, subtag_add_tags in subtags_list:
                subtags[subtag_name if subtag_name else 'None'] = (subtag_descr, subtag_add_tags)

            site_host_tags[name if name else 'None'] = {
                'description': description,
                'subtags': subtags,
            }

    site_tags = merge_dict(check_mk_config.get('host_tags', {}), site_host_tags)

    actions['check_mk_create_{}_site'.format(site)] = {
        'command': 'omd create {}'.format(site),
        'unless': 'omd sites | grep -q -e "^{} "'.format(site),
        'needs': [
            'action:install_check_mk',
        ],
    }

    actions['check_mk_start_{}_site'.format(site)] = {
        'command': 'sudo -u {site} omd start'.format(site=site),
        'unless': 'omd status {site} | grep "Overall state:" | grep -q "running"'.format(site=site),
        'needs': [
            'action:check_mk_create_{}_site'.format(site),
        ],
    }

    actions['check_mk_stop_{}_site'.format(site)] = {
        'command': 'sudo -u {site} omd stop'.format(site=site),
        'unless': 'omd status {site} | grep "Overall state:" | grep -q "stopped"'.format(site=site),
        'triggered': True,
        'needs': [
            'action:check_mk_create_{}_site'.format(site),
        ],
    }

    actions['check_mk_restart_{}_site'.format(site)] = {
        'command': 'sudo -u {site} omd restart'.format(site=site),
        'triggered': True,
        'needs': [
            'action:check_mk_create_{}_site'.format(site),
        ],
    }

    actions['check_mk_recompile_{}_site'.format(site)] = {
        'command': 'sudo -i -u {site} {folder}/bin/check_mk -O'.format(
            site=site,
            folder=site_folder,
        ),
        'triggered': True,
        'needs': [
            'action:check_mk_create_{}_site'.format(site),
        ],
    }

    htpasswd = []
    check_mk_users = [
        '\'automation\': {'
        + '\'alias\': u\'Check_MK Automation - used for calling web services\', '
        + '\'locked\': False, '
        + '\'roles\': [\'admin\'], '
        + '\'language\': \'en\', '
        + '\'automation_secret\': \''
        + repo.libs.pw.get('check_mk_automation_secret_{}_{}'.format(node.name, site))
        + '\'},',
    ]

    contacts = [
        "'automation': {'alias': u'Check_MK Automation - used for calling web services', 'notifications_enabled': False, 'pager': '', 'email': u'', 'contactgroups': []},",
    ]

    for admin in site_config.get('admins', []):
        admin_config = check_mk_config.get('users', {}).get(admin, {})
        if not admin_config.get('enabled', False):
            continue

        check_mk_users += [
            'u\'{user}\': {{\'alias\': u\'{alias}\', \'locked\': False, \'roles\': [\'admin\']}}, '.format(
                user=admin,
                alias=admin_config.get('alias', admin),
            ),
        ]

        contacts += [
            "u'{user}': {{".format(
                user=admin,
            ),
            "  'alias': u'{alias}',".format(
                alias=admin_config.get('alias', admin),
            ),
            "  'disable_notifications': {},".format(admin_config.get('disable_notifications', False)),
            "  'email': u'{email}',".format(
                email=admin_config.get('email', ''),
            ),
        ]

        if 'contactgroups' in admin_config:
            contacts += [
                "  'contactgroups': {},".format(admin_config['contactgroups'])
            ]

        if 'pager' in admin_config:
            contacts += [
                "  'pager': '{}',".format(admin_config['pager'])
            ]

        contacts += [
            "  'notification_rules': [",
        ]
        for notification_rule, notification_rule_config in \
                sorted(admin_config.get('notification_rules', {}).items(), key=sort_by_prio):

            if notification_rule_config.get('type', '') == 'pushover':
                contacts += [
                    "    {",
                    "      'comment': u'{}',".format(notification_rule),
                    "      'contact_users': [u'{}'],".format(admin),
                    "      'description': u'{}',".format(notification_rule_config.get('description', notification_rule)),
                    "      'disabled': False,",
                    "      'docu_url': '',",
                    "      'match_host_event': {},".format(notification_rule_config.get('match_host_event', [])),
                    "      'match_service_event': {},".format(notification_rule_config.get('match_service_event', [])),
                    "      'notify_plugin': ("
                    "        'pushover',",
                    "        {",
                    "          'api_key': '{}',".format(notification_rule_config.get('api_key', '')),
                    "          'recipient_key': '{}',".format(notification_rule_config.get('recipient_key', '')),
                    "          'url_prefix': '{}/check_mk/'".format(site_url),
                    "        },",
                    "      ),",
                    "    },",
                ]

        contacts += [
            "  ],",
        ]

        if admin_config.get('fallback_contact', False):
            contacts += [
                "  'fallback_contact': {},".format(admin_config.get('fallback_contact', False)),
            ]

        contacts += [
            '},',
        ]

        salt = repo.libs.pw.get(
            'check_mk_node_{}_site_{}_user_{}_salt'.format(node.name, site, admin),
            length=8,
        )

        passwd = admin_config.get(
            'password',
            repo.libs.pw.get('check_mk_node_{}_site_{}_user_{}_password').format(node.name, site, admin)
        )

        # NEEDS to be md5, since check_mk only knows how to deal with those
        hashed_password = md5_crypt.using(salt=salt).hash(passwd)

        htpasswd += ['{}:{}'.format(admin, hashed_password)]

    for user in site_config.get('users', []):
        user_config = check_mk_config.get('users', {}).get(user, {})
        if not user_config.get('enabled', False):
            continue

        check_mk_users += [
            'u\'{user}\': {{\'alias\': u\'{user}\', \'locked\': False, \'roles\': [\'user\']}}, '.format(user=user),
        ]
        contacts += [
            "u'{user}': {{'alias': u'{user}', 'email': u'{email}'}},".format(
                user=user,
                email=user_config.get('email', ''),
            )
        ]

        salt = repo.libs.pw.get(
            'check_mk_node_{}_site_{}_user_{}_salt'.format(node.name, site, user),
            length=8,
        )

        passwd = user_config.get(
            'password',
            repo.libs.pw.get('check_mk_node_{}_site_{}_user_{}_password').format(node.name, site, user)
        )

        # NEEDS to be md5, since check_mk only knows how to deal with those
        hashed_password = md5_crypt.using(salt=salt).hash(passwd)

        htpasswd += ['{}:{}'.format(user, hashed_password)]

    files['{site_folder}/etc/htpasswd'.format(site_folder=site_folder)] = {
        'content': '\n'.join(htpasswd) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
    }

    omd_configs = {
        'ADMIN_MAIL': admin_email,
        'LIVESTATUS_TCP': 'on' if site_config.get('livestatus', False) else 'off',
        'LIVESTATUS_TCP_PORT': site_config.get('livestatus_port', 6557),
        'MKEVENTD_SNMPTRAP': 'on',
    }

    if check_mk_config.get('beta', False):
        omd_configs['LIVESTATUS_TCP_ONLY_FROM'] = ' '.join(site_config.get('livestatus_allowed_ips', []))

    for key, value in omd_configs.items():
        if value == '':
            continue

        actions['omd_{}_{}'.format(site, key)] = {
            'command': "omd config {} set {} '{}'".format(site, key, value),
            'unless': 'test "$(omd config {} show {})" = "{}"'.format(site, key, value),
            'needs': [
                'action:check_mk_create_{}_site'.format(site)
            ],
            'preceded_by': [
                'action:check_mk_stop_{}_site'.format(site),
            ],
            'needed_by': [
                'action:check_mk_start_{}_site'.format(site)
            ],
        }

    files['{}/.forward'.format(site_folder)] = {
        'content': admin_email + '\n',
        'owner': site,
        'group': site,
        'mode': '0644',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
    }

    files['{}/etc/check_mk/main.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            'filesystem_default_levels["levels"] = ( 95.0, 99.0 )',
            # "ntp_default_levels = (15, 500.0, 1000.0)",
            "if_inventory_portstates = ['1', '2', '5']",
            ] +
            site_config.get('extra_nagios_config', []) +
            [
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0644',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    # multisite.d
    multisites = [
        "  '{}': {{".format(site),
        "    'status_host': None,",
        "    'user_sync': 'all',",
        "    'replication': '',",
        "    'user_login': True,",
        "    'insecure': False,",
        "    'disable_wato': True,",
        "    'disabled': False,",
        "    'alias': u'Local site {}',".format(site),
        "    'replicate_mkps': False,",
        "    'timeout': 10,",
        "    'persist': False,",
        "    'replicate_ec': False,",
        "    'multisiteurl': ''",
        "},",
    ]

    for server in site_config.get('livestatus_server'):
        multisites += [
            "  '{}_on_{}': {{".format(server.get('site', ''), server.get('name', '')),
            "    'status_host': None,",
            "    'user_sync': 'all',",
            "    'user_login': True,",
            "    'insecure': False,",
            "    'disabled': False,",
            "    'replication': '',",
            "    'multisiteurl': '',",
            "    'replicate_mkps': True,",
            "    'url_prefix': 'https://{}/{}/',".format(server.get('hostname', ''), server.get('site', '')),
            "    'socket': 'tcp:{}:{}',".format(server.get('ips', [])[0], server.get('port', 6557)),
            "    'disable_wato': True,",
            "    'alias': u'{} on {}',".format(server.get('site', ''), server.get('name', '')),
            "    'timeout': 10,",
            "    'persist': True,",
            "    'replicate_ec': True",
            "  },",
        ]

    files['{}/etc/check_mk/multisite.d/sites.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            'sites.update({',
            ] + multisites + [
            '})',
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }
    files['{}/etc/check_mk/multisite.d/wato/global.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            'wato_use_git = True',
            "mkeventd_notify_contactgroup = 'all'",
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    wato_host_tags = []
    for host_tag, host_tag_config in sorted(site_tags.items(), key=sort_by_prio):
        wato_host_tags += [
            # we need to do this limbo, since check_mk is still 2.7 and we need the u flag on the string
            # ('agent', u'Agent type', [
            #     ('cmk-agent', u'Check_MK Agent (Server)', ['tcp']),
            #     ('snmp-only', u'SNMP (Networking device, Appliance)', ['snmp']),
            #     ('snmp-v1', u'Legacy SNMP device (using V1)', ['snmp']),
            #     ('snmp-tcp', u'Dual: Check_MK Agent + SNMP', ['snmp', 'tcp']),
            #     ('ping', u'No Agent', [])
            # ]),

            "  ('{host_tag}', u'{description}', [".format(
                host_tag=host_tag,
                description=host_tag_config.get('description', '')
            ),
        ]

        for subtag_name, subtag_config in host_tag_config.get('subtags', {}).items():
            wato_host_tags += [
                "    ('{name}', u'{description}', [{tags}]),".format(
                    name=subtag_name,
                    description=subtag_config[0],
                    tags=', '.join(map(lambda x: "'{}'".format(x), subtag_config[1]))
                ).replace("'None'", "None"),
                ]

        wato_host_tags += [
            "  ]),"
        ]

    wato_aux_tags = []
    for aux_tag, aux_tag_config in sorted(
            merge_dict(check_mk_config.get('aux_tags', {}), site_config.get('aux_tags', {})).items(),
            key=sort_by_prio):

        wato_aux_tags += [
            # we need to do this limbo, since check_mk is still 2.7 and we need the u flag on the string
            "  ('{name}', u'{description}'),".format(
                name=aux_tag,
                description=aux_tag_config.get('description', ''),
            ),
        ]

    files['{}/etc/check_mk/multisite.d/wato/hosttags.mk'.format(site_folder)] = {
        'content': '\n'.join([
                                 '# Written by Bundlewrap',
                                 '# encoding: utf-8',
                                 '',
                                 'wato_host_tags += [',
                             ] +
                             wato_host_tags +
                             [
                                 ']',
                                 'wato_aux_tags += [',
                             ] +
                             wato_aux_tags +
                             [
                                 ']',
                             ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0644',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    files['{}/etc/check_mk/multisite.d/wato/users.mk'.format(site_folder)] = {
        'content': '\n'.join([
                                 '# Written by Bundlewrap',
                                 '# encoding: utf-8',
                                 '',
                                 'multisite_users.update({',
                             ] +
                             check_mk_users +
                             ['})', ]
                             ) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    # conf.d
    files['{}/etc/check_mk/conf.d/wato/contacts.mk'.format(site_folder)] = {
        'content': '\n'.join([
                                 '# Written by Bundlewrap',
                                 '# encoding: utf-8',
                                 '',
                                 'contacts.update({',
                             ] +
                             contacts +
                             ['})', ]
                             ) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    files['{}/etc/check_mk/conf.d/wato/notifications.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            "notification_rules += [{'allow_disable': True,",
            "  'comment': u'',",
            "  'contact_all': False,",
            "  'contact_all_with_email': False,",
            "  'contact_object': True,",
            "  'description': u'html',",
            "  'disabled': False,",
            "  'docu_url': '',",
            "  'notify_plugin': (u'mail', {})}]",
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],

    }

    # {u'muetze': {'force_authuser_webservice': False, 'locked': False, 'roles': ['admin'], 'force_authuser': False,
    #              'alias': u'Muetze', 'start_url': None},
    #  'automation': {'alias': u'Check_MK Automation - used for calling web services', 'locked': False,
    #                 'roles': ['admin'], 'language': 'en', 'automation_secret': '3OlTaam37oEo6DaHkE8RtPkGhaVntNjh'}

    files['{}/etc/check_mk/conf.d/wato/global.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            "notification_fallback_email = '{}'".format(site_config.get('admin_email', '')),
            "use_new_descriptions_for = ['df',",
            " 'df_netapp',",
            " 'df_netapp32',",
            " 'esx_vsphere_datastores',",
            " 'hr_fs',",
            " 'vms_diskstat.df',",
            " 'zfsget',",
            " 'ps',",
            " 'ps.perf',",
            " 'wmic_process',",
            " 'services',",
            " 'logwatch',",
            " 'logwatch.groups',",
            " 'cmk-inventory',",
            " 'hyperv_vms',",
            " 'ibm_svc_mdiskgrp',",
            " 'ibm_svc_system',",
            " 'ibm_svc_systemstats.diskio',",
            " 'ibm_svc_systemstats.iops',",
            " 'ibm_svc_systemstats.disk_latency',",
            " 'ibm_svc_systemstats.cache',",
            " 'casa_cpu_temp',",
            " 'cmciii.temp',",
            " 'cmciii.psm_current',",
            " 'cmciii_lcp_airin',",
            " 'cmciii_lcp_airout',",
            " 'cmciii_lcp_water',",
            " 'etherbox.temp',",
            " 'liebert_bat_temp',",
            " 'nvidia.temp',",
            " 'ups_bat_temp',",
            " 'innovaphone_temp',",
            " 'enterasys_temp',",
            " 'raritan_emx',",
            " 'raritan_pdu_inlet',",
            " 'mknotifyd',",
            " 'mknotifyd.connection',",
            " 'postfix_mailq',",
            " 'nullmailer_mailq',",
            " 'barracuda_mailqueues',",
            " 'qmail_stats',",
            " 'http',",
            " 'mssql_backup',",
            " 'mssql_counters.cache_hits',",
            " 'mssql_counters.transactions',",
            " 'mssql_counters.locks',",
            " 'mssql_counters.sqlstats',",
            " 'mssql_counters.pageactivity',",
            " 'mssql_counters.locks_per_batch',",
            " 'mssql_counters.file_sizes',",
            " 'mssql_databases',",
            " 'mssql_datafiles',",
            " 'mssql_tablespaces',",
            " 'mssql_transactionlogs',",
            " 'mssql_versions']",
            "tcp_connect_timeout = 10.0",
            "enable_rulebased_notifications = True",
            "inventory_check_interval = 120",
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    define_hostgroups = []
    hostgroups = []
    for host_group, host_group_config in sorted(
            merge_dict(check_mk_config.get('host_groups', {}), site_config.get('host_groups', {})).items(),
            key=sort_by_prio):

        define_hostgroups += [
            "  '{}': u'{}',".format(host_group, host_group_config.get('description', {})),
        ]

        hostgroups += [
            "  ('{name}', {tags}, {hosts}, {{'description': u'{description}'}}),".format(
                name=host_group,
                tags='[{}]'.format(", ".join(map(lambda x: "'{}'".format(x), host_group_config.get('tags', [])))),
                hosts=format_hosts(host_group_config.get('hosts', "ALL_HOSTS")),
                description=host_group_config.get('description', {})
            ),
        ]

    define_contactgroups = [
        "  'all': u'Everything',",
    ]
    host_contactgroups = [
        "  ('all', [], ALL_HOSTS, {'description': u'Admins'}),",
    ]
    service_contactgroups = [
        "  ('all', [], ALL_HOSTS, ALL_SERVICES, {'description': u'admins'}),",
    ]

    for contact_group, contact_group_config in sorted(
            merge_dict(check_mk_config.get('contact_groups', {}), site_config.get('contact_groups', {})).items(),
            key=sort_by_prio):

        define_contactgroups += [
            "  '{}': u'{}',".format(contact_group, contact_group_config.get('description', {})),
        ]
        host_contactgroups += [
            "  ('{name}', {tags}, {hosts}, {{'description': u'{description}'}}),".format(
                name=contact_group,
                tags='[{}]'.format(
                    ", ".join(map(lambda x: "'{}'".format(x), contact_group_config.get('hosts', {}).get('tags', [])))
                ),
                hosts=format_hosts(contact_group_config.get('hosts', {}).get('hosts', "ALL_HOSTS")),
                description=contact_group_config.get('hosts', {}).get('description', {})
            ),
        ]
        service_contactgroups += [
            "  ('{name}', {tags}, {hosts}, {services}, {{'description': u'{description}'}}),".format(
                name=contact_group,
                tags='[{}]'.format(
                    ", ".join(map(lambda x: "'{}'".format(x), contact_group_config.get('sevices', {}).get('tags', [])))
                ),
                hosts=format_hosts(contact_group_config.get('services', {}).get('hosts', "ALL_HOSTS")),
                services=format_services(contact_group_config.get('services', {}).get('services', 'ALL_SERVICES')),
                description=contact_group_config.get('services', {}).get('description', {})
            ),
        ]

    files['{}/etc/check_mk/conf.d/wato/groups.mk'.format(site_folder)] = {
        'content': '\n'.join([
                                 '# Written by Bundlewrap',
                                 '# encoding: utf-8',
                                 '',
                                 "if type(define_hostgroups) != dict:",
                                 "    define_hostgroups = {}",
                                 "define_hostgroups.update({",
                             ] +
                             define_hostgroups +
                             [
                                 "})",
                                 "",
                                 "if type(define_contactgroups) != dict:",
                                 "    define_contactgroups = {}",
                                 "define_contactgroups.update({",
                             ] +
                             define_contactgroups +
                             [
                                 "})",
                             ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0644',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    rules = [
        '# Written by Bundlewrap',
        '# encoding: utf-8',
        '',
    ]

    rules += [
        'host_groups = [',
    ]
    rules += hostgroups
    rules += [
        '] + host_groups',
        '',
    ]

    rules += [
        'host_contactgroups = [',
    ]
    rules += host_contactgroups
    rules += [
        '] + host_contactgroups',
        '',
    ]
    rules += [
        'service_contactgroups = [',
    ]
    rules += service_contactgroups
    rules += [
        '] + service_contactgroups',
        '',
    ]

    rules += generate_rules(merge_dict(check_mk_config.get('global_rules', {}), site_config.get('rules', {})))

    files['{}/etc/check_mk/conf.d/wato/rules.mk'.format(site_folder)] = {
        'content': '\n'.join(rules) + '\n',
        'owner': site,
        'group': site,
        'mode': '0644',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    # generate folders and hosts
    for folder, folder_config in site_config.get('folders', {}).items():
        directories['{}/etc/check_mk/conf.d/wato/{}'.format(site_folder, folder)] = {
            'owner': site,
            'group': site,
            'mode': '0755',
            'needs': [
                'action:check_mk_create_{}_site'.format(site)
            ],
        }

        rules = generate_rules(folder_config.get('rules', {}))

        files['{}/etc/check_mk/conf.d/wato/{}/rules.mk'.format(site_folder, folder)] = {
            'content': '\n'.join(rules) + '\n',
            'owner': site,
            'group': site,
            'mode': '0644',
            'needs': [
                'action:check_mk_create_{}_site'.format(site)
            ],
            'triggers': [
                'action:check_mk_recompile_{}_site'.format(site),
            ],
        }

        files['{}/etc/check_mk/conf.d/wato/{}/.wato'.format(site_folder, folder)] = {
            'content': '\n'.join([
                "{{"
                "'lock': False, 'attributes': {{}}, "
                "'num_hosts': {num_hosts}, 'lock_subfolders': False, "
                "'title': u'{title}'}}".format(
                    num_hosts=len(folder_config.get('hosts', [])),
                    title=folder,
                )
            ]) + '\n',
            'owner': site,
            'group': site,
            'mode': '0644',
            'needs': [
                'action:check_mk_create_{}_site'.format(site),
            ],
            'triggers': [
                'action:check_mk_recompile_{}_site'.format(site),
            ],
        }

        all_hosts = []
        extra_host_config_parents = []
        ipaddresses = []
        snmp_communities = []
        host_attributes = []

        rediscover_hosts = []
        for host in folder_config.get('hosts', []):
            if isinstance(host, str):
                host_node = repo.get_node(host)
                host_node_check_mk_config = host_node.metadata.get('check_mk', {})
                host = {
                    'hostname': host_node.hostname,
                    'port': host_node_check_mk_config.get('port', 6556),
                    'tags': sorted(list(dict.fromkeys(host_node_check_mk_config.get('tags', [])))),  # uniq and sorted
                    'attributes': host_node_check_mk_config.get('attributes', {}),
                }

            if host.get('hostname', '') == '':
                continue

            tags = host.get('tags', [])
            attributes = host.get('attributes', {})

            for name, tag_config in sorted(site_tags.items(), key=sort_by_prio):
                description = tag_config.get('description', None)
                subtags = tag_config.get('subtags', [])
                # if it is configured, do not change
                if 'tag_{}'.format(name) not in attributes:
                    for subtag_name, subtag_config in subtags.items():
                        if subtag_name in tags:
                            attributes['tag_{}'.format(name)] = subtag_name
                            break
                    else:
                        attributes['tag_{}'.format(name)] = None

            all_hosts += [
                # TODO: move prod to tags
                '  "{hostname}|site:{site}|prod|wato|{tags}|/" + FOLDER_PATH + "/",'.format(
                    hostname=host['hostname'],
                    site=site,
                    tags="|".join(tags)
                ),
            ]

            parents = host.get('parents', [])

            if parents:
                extra_host_config_parents += [
                    "  ('{hostname}', {parents}),".format(
                        hostname=host['hostname'],
                        parents=map(lambda x: "'{}'".format(x), parents)
                    ),
                ]

            ip = host.get('ip_address', None)

            if ip:
                ipaddresses += [
                    "  '{hostname}': '{ip}',".format(
                        hostname=host['hostname'],
                        ip=ip,
                    ),
                ]
                attributes['ipaddress'] = ip

            snmp_community = host.get('snmp_community', None)

            if snmp_community:
                snmp_communities += [
                    "  '{hostname}': '{community}',".format(
                        hostname=host['hostname'],
                        community=snmp_community,
                    ),
                ]
                attributes['snmp_community'] = snmp_community

            if attributes:
                host_attributes += [
                    "  '{hostname}': {attributes},".format(
                        hostname=host['hostname'],
                        attributes=attributes,
                    ),
                ]

            rediscover_hosts += [host['hostname'], ]

            actions['check_mk_rediscover_host_{}'.format(host['hostname'])] = {
                'command': 'sudo -i -u {site} {folder}/bin/check_mk -II {host}'.format(
                    site=site,
                    folder=site_folder,
                    host=host['hostname']
                ),
                'triggered': True,
            }

        files['{}/etc/check_mk/conf.d/wato/{}/hosts.mk'.format(site_folder, folder)] = {
            'content': '\n'.join([
                                     '# Written by Bundlewrap',
                                     '# encoding: utf-8',
                                     '',
                                     "all_hosts += [",
                                 ] +
                                 all_hosts +
                                 [
                                     "]",
                                     "",
                                     "# Explicit IPv4 addresses",
                                     "ipaddresses.update({",
                                 ] +
                                 ipaddresses +
                                 [
                                     "})",
                                     "",
                                     "# Explicit SNMP communities",
                                     "explicit_snmp_communities.update({",
                                 ] +
                                 snmp_communities +
                                 [
                                     "})",
                                     "",
                                     "# Settings for parents",
                                     "extra_host_conf.setdefault('parents', []).extend([",
                                 ] +
                                 extra_host_config_parents +
                                 [
                                     "])",
                                     "# Host attributes (needed for WATO)",
                                     "host_attributes.update({",
                                 ] +
                                 host_attributes +
                                 [
                                     "})",
                                 ]) + '\n',
            'owner': site,
            'group': site,
            'mode': '0644',
            'needs': [
                'action:check_mk_create_{}_site'.format(site),
            ],
            'triggers': [
                            'action:check_mk_recompile_{}_site'.format(site),
                        ] + ["action:check_mk_rediscover_host_{}".format(host) for host in rediscover_hosts]
        }

    # mkevent.d
    # TODO: generate from metadata
    global_rules = []
    rule_packs = [
        {'disabled': False,
         'rules': [
             {
                 'comment': '',
                 'count': {
                     'count': 1,
                     'algorithm': 'interval',
                     'period': 86400,
                     'separate_application': True,
                     'count_ack': False,
                     'separate_match_groups': True,
                     'separate_host': True
                 },
                 'cancel_action_phases': 'always',
                 'set_application': 'auth',
                 'description': 'Authentication Failed',
                 'autodelete': False,
                 'cancel_actions': [],
                 'drop': False,
                 'match_application': '1.3.6.1.6.3.1.1.5.5',
                 'hits': 0,
                 'actions': [],
                 'invert_matching': False,
                 'disabled': False,
                 'state': 2,
                 'sl': 0,
                 'docu_url': '',
                 'id': 'auth_fail',
                 'match': ''
             },
             {
                 'comment': '',
                 'set_application': 'link',
                 'cancel_action_phases': 'always',
                 'docu_url': '',
                 'description': 'Generate Warning when link goes up',
                 'autodelete': False,
                 'cancel_actions': [],
                 'drop': False,
                 'hits': 0,
                 'actions': [],
                 'id': 'link_up_warn',
                 'disabled': False,
                 'state': 1,
                 'sl': 0,
                 'match_application': '1.3.6.1.6.3.1.1.5.4',
                 'set_text': 'Link of Port \\1 is up (\\2)',
                 'invert_matching': False,
                 'match': '1.3.6.1.2.1.2.2.1.8.([0-9]+): ([12])'
             },
             {
                 'comment': '',
                 'set_application': 'link',
                 'cancel_action_phases': 'always',
                 'description': 'Generate Warning when link goes down',
                 'autodelete': False,
                 'cancel_actions': [],
                 'drop': False,
                 'match_application': '1.3.6.1.6.3.1.1.5.3',
                 'actions': [],
                 'invert_matching': False,
                 'disabled': False,
                 'state': 1,
                 'sl': 0,
                 'docu_url': '',
                 'set_text': 'Link of Port \\1 is down (\\2)',
                 'id': 'link_down_warn',
                 'match': '1.3.6.1.2.1.2.2.1.8.([0-9]+): ([12])'
             },
             {
                 'comment': '',
                 'set_application': 'link',
                 'cancel_action_phases': 'always',
                 'description': 'Generate Warning when link goes up / down',
                 'autodelete': False,
                 'cancel_actions': [],
                 'drop': False,
                 'match_application': '1.3.6.1.6.3.1.1.5.[34]',
                 'hits': 3,
                 'actions': [],
                 'invert_matching': False,
                 'disabled': False,
                 'state': 1,
                 'sl': 0,
                 'docu_url': '',
                 'set_text': 'Link of Port \\1 is \\2',
                 'id': 'link',
                 'match': '1.3.6.1.2.1.2.2.1.8.([0-9]+): ([12])'
             },
             {
                 'comment': '',
                 'hits': 18,
                 'description': 'localSNMPTraps',
                 'autodelete': False,
                 'cancel_actions': [],
                 'drop': False,
                 'cancel_action_phases': 'always',
                 'actions': [],
                 'invert_matching': False,
                 'disabled': False,
                 'state': -1,
                 'sl': 0,
                 'docu_url': '',
                 'id': 'snmp_log',
                 'match': ''
             }
         ],
         'hits': 24,
         'id': 'snmp_traps',
         'title': 'SNMPTraps',
         }
    ]

    files['{}/etc/check_mk/mkeventd.d/wato/rules.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            'rules += [',
            ',\n'.join(global_rules),
            ']',
            '',
            'rule_packs += [',
            ',\n'.join(map(lambda x: str(x), rule_packs)),
            ']',
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0640',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    # TODO: patch sha512 support into htpasswd authentication ( ~/share/check_mk/web/plugins/userdb/htpasswd.py )
