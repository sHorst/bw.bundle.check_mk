from passlib.hash import md5_crypt
from bundlewrap.utils.dicts import merge_dict

supported_versions = {
    '1.4.0p31': 'cbbd46be8b486c12f74e4368a1d8e608864aaa105bf85c165e7604fcba7668f0',
    '1.5.0b3': '3c56922dbd7e95b451f758782b37880649d0adc0ddad43918badf555562b5e27',
    '1.6.0p9': 'ad79a72cc0cc956ee62c18858db99d4e308276823c34968807e9a34b3f13e9db',
}


def sort_by_prio(x):
    if isinstance(x, str):
        return '10_{}'.format(x)

    if isinstance(x[1], dict):
        prio = x[1].get('prio', 10)
    else:
        prio = 10

    return '{}_{}'.format(prio, x[0])


def sort_hostnames(x):
    if isinstance(x, dict):
        return x.get('hostname', '')

    return x


def sorted_dict(x):
    return dict(sorted(x.items(), key=sort_by_prio))


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
        # only use u for special keys
        if isinstance(dict_value, str) and dict_key in ['description']:
            output += ["'{}': u'{}'".format(dict_key, dict_value), ]
        elif isinstance(dict_value, str):
            output += ["'{}': '{}'".format(dict_key, dict_value), ]
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
    elif isinstance(rule_config, dict):
        # return rule_config
        return dict_to_string_python_2(rule_config)
    else:
        return rule_config


def generate_rules(config_rules):
    output_rules = []

    for rule, rule_config in sorted(config_rules.items(), key=sort_by_prio):
        if isinstance(rule_config, list):
            output_rules += [
                'globals().setdefault(\'{}\', [])'.format(rule),
                '',
            ]

            if rule == 'only_hosts':
                output_rules += [
                    'if {} is None:'.format(rule),
                    '    {} = []'.format(rule),
                    '',
                ]

            output_rules += [
                '{} = ['.format(rule)
            ]
            output_rules += map(lambda x: "{},".format(format_rule(x)), rule_config)
            output_rules += [
                '] + {}'.format(rule),
                '',
                ''
            ]
        elif isinstance(rule_config, dict):
            for subrule, subrule_config in sorted(rule_config.items(), key=sort_by_prio):
                output_rules += [
                    '{}.setdefault(\'{}\', [])'.format(rule, subrule),
                    '',
                    '{}[\'{}\'] = ['.format(rule, subrule),
                ]
                output_rules += map(lambda x: "{},".format(format_rule(x)), subrule_config)
                output_rules += [
                    '] + {}[\'{}\']'.format(rule, subrule),
                    '',
                    ''
                ]

    return output_rules


check_mk_config = node.metadata.get('check_mk', {})

CHECK_MK_VERSION = check_mk_config.get('version', '1.6.0p9')

if CHECK_MK_VERSION not in supported_versions.keys():
    raise BundleError(_(
        "unsupported version {version} for {item} in bundle '{bundle}'"
    ).format(
        version=CHECK_MK_VERSION,
        bundle=bundle.name,
        item=item_id,
    ))

CHECK_MK_DEB_FILE = 'check-mk-raw-{}_0.buster_amd64.deb'.format(CHECK_MK_VERSION)
CHECK_MK_DEB_FILE_SHA256 = supported_versions[CHECK_MK_VERSION]

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

    for icon in ['debian.png', 'netgear.png', 'ubnt.png', 'vmware.png', 'vmware2.png']:
        files['{site_folder}/local/share/check_mk/web/htdocs/images/icons/{icon}'.format(site_folder=site_folder, icon=icon)] = {
            'source': 'icons/{icon}'.format(icon=icon),
            'owner': site,
            'group': site,
            'mode': '0644',
            'content_type': 'binary',
            'needs': [
                'action:check_mk_create_{}_site'.format(site)
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
        + repo.vault.password_for('check_mk_automation_secret_{}_{}'.format(node.name, site)).value
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

        salt = repo.vault.password_for(
            'check_mk_node_{}_site_{}_user_{}_salt'.format(node.name, site, admin),
            length=8,
        ).value

        passwd = admin_config.get(
            'password',
            repo.vault.password_for('check_mk_node_{}_site_{}_user_{}_password').format(node.name, site, admin)
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

        salt = repo.vault.password_for(
            'check_mk_node_{}_site_{}_user_{}_salt'.format(node.name, site, user),
            length=8,
        )

        passwd = user_config.get(
            'password',
            repo.vault.password_for('check_mk_node_{}_site_{}_user_{}_password').format(node.name, site, user)
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
        'LIVESTATUS_TCP_TLS': 'on',
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
        'mode': '0660',
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
        'mode': '0660',
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
        "    'replication': None,",
        "    'user_login': True,",
        "    'insecure': False,",
        "    'disable_wato': True,",
        "    'disabled': False,",
        "    'alias': u'Local site {}',".format(site),
        "    'replicate_mkps': False,",
        "    'socket': ('local', None),",
        "    'timeout': 10,",
        "    'persist': False,",
        "    'replicate_ec': False,",
        "    'multisiteurl': '',",
        "  },",
    ]

    for server in site_config.get('livestatus_server'):
        multisites += [
            "  '{}_on_{}': {{".format(server.get('site', ''), server.get('name', '').replace('.', '_')),
            "    'status_host': None,",
            "    'user_sync': 'all',",
            "    'user_login': True,",
            "    'insecure': False,",
            "    'disabled': False,",
            "    'replication': None,",
            "    'multisiteurl': '',",
            "    'replicate_mkps': True,",
            "    'url_prefix': 'https://{}/{}/',".format(server.get('hostname', ''), server.get('site', '')),
            "    'socket': {},".format(('tcp', {'tls': ('encrypted', {'verify': False}), 'address': (server.get('ips', [])[0], server.get('port', 6557))})),
            "    'disable_wato': True,",
            "    'alias': u'{} on {}',".format(server.get('site', ''), server.get('name', '')),
            "    'timeout': 10,",
            "    'persist': True,",
            "    'replicate_ec': True,",
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
        # ignore this tag in the config
        if host_tag_config.get('notInTagConfig', False):
            continue

        # we need to do this limbo, since check_mk is still 2.7 and we need the u flag on the string
        tmp_host_tag = []

        if host_tag_config.get('topic', None):
            tmp_host_tag += [
                "'topic': u'{topic}'".format(
                    topic=host_tag_config['topic']
                ),
            ]

        tmp_tags = []
        for subtag_name, subtag_config in host_tag_config.get('subtags', {}).items():
            tmp_tags += ['{' + "'aux_tags': [{tags}], 'id': '{id}', 'title': u'{title}'".format(
                    id=subtag_name,
                    title=subtag_config[0],
                    tags=', '.join(map(lambda x: "'{}'".format(x), subtag_config[1]))
                ).replace("'None'", "None") + '}',
                ]
        tmp_host_tag += ["'tags': [" + ', '.join(tmp_tags) + ']', ]

        tmp_host_tag += ["'id': '{id}'".format(id=host_tag)]
        tmp_host_tag += ["'title': u'{title}'".format(title=host_tag_config.get('title', ''))]

        wato_host_tags += ['{' + ', '.join(tmp_host_tag) + '}', ]
    # {
    #     'topic': u'Services',
    #     'tags': [
    #         {'aux_tags': [], 'id': None, 'title': u'Nein'},
    #         {'aux_tags': ['ftp'], 'id': 'ftp_21', 'title': u'Ja'},
    #         {'aux_tags': ['ftp'], 'id': 'ftp_12121', 'title': u'Ja (port 12121)'}], 'id': 'FTP',
    #     'title': u'ProFTP Server'
    # },

    wato_aux_tags = []
    for aux_tag, aux_tag_config in sorted(
            merge_dict(check_mk_config.get('aux_tags', {}), site_config.get('aux_tags', {})).items(),
            key=sort_by_prio):

        wato_aux_tags += [
            # we need to do this limbo, since check_mk is still 2.7 and we need the u flag on the string
            '{' +
            "'topic': u'{topic}', 'id': '{name}', 'title': u'{title}'".format(
                topic=aux_tag_config.get('topic', 'Services'),
                name=aux_tag,
                title=aux_tag_config.get('title', ''),
            ) + '}',
        ]

    wato_tags_update = '{' + "'aux_tags': [{aux_tags}], 'tag_groups': [{tag_groups}]".format(
        aux_tags=', '.join(wato_aux_tags),
        tag_groups=', '.join(wato_host_tags),
    ) + '}'

    files['{}/etc/check_mk/multisite.d/wato/tags.mk'.format(site_folder)] = {
        'content': '\n'.join([
                                 '# Written by Bundlewrap',
                                 '# encoding: utf-8',
                                 '',
                                 'wato_tags.update({update_tags})'.format(update_tags=wato_tags_update),
                             ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0660',
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
    files['{}/etc/check_mk/conf.d/wato/tags.mk'.format(site_folder)] = {
        'content': '\n'.join([
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            'tag_config.update({update_tags})'.format(update_tags=wato_tags_update),
        ]) + '\n',
        'owner': site,
        'group': site,
        'mode': '0660',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

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
            "  'contact_match_groups': {contact_match_groups},".format(contact_match_groups=['all']),
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
            "{{'condition': {condition},\n"
            " 'options': {{'description': u'{description}'}},\n"
            " 'value': '{name}'}}".format(
                name=host_group,
                condition=host_group_config.get('condition', {}),
                description=host_group_config.get('description', {})
            ),
        ]

    define_contactgroups = [
        "  'all': u'Everything',",
    ]
    host_contactgroups = [
        "{'condition': {}, 'options': {'description': u'Admins'}, 'value': 'all'}",
    ]
    service_contactgroups = [
        "{'condition': {}, 'options': {'description': u'admins'}, 'value': 'all'}",
    ]

    for contact_group, contact_group_config in sorted(
            merge_dict(check_mk_config.get('contact_groups', {}), site_config.get('contact_groups', {})).items(),
            key=sort_by_prio):

        define_contactgroups += [
            "  '{}': u'{}',".format(contact_group, contact_group_config.get('description', {})),
        ]
        host_contactgroups += [
            "{{'condition': {{{condition}}}, 'options': {{'description': u'{description}'}}, 'value': '{name}'}}".format(
                name=contact_group,
                condition=contact_group_config.get('hosts', {}).get('condition', ''),
                description=contact_group_config.get('hosts', {}).get('description', {})
            ),
        ]
        service_contactgroups += [
            "{{'condition': {{{condition}}}, 'options': {{'description': u'{description}'}}, 'value': '{name}'}}".format(
                name=contact_group,
                condition=contact_group_config.get('services', {}).get('condition', ''),
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
        'mode': '0660',
        'needs': [
            'action:check_mk_create_{}_site'.format(site)
        ],
        'triggers': [
            'action:check_mk_recompile_{}_site'.format(site),
        ],
    }

    rules = merge_dict(check_mk_config.get('global_rules', {}), site_config.get('rules', {}))
    rules['host_groups'] = hostgroups
    rules['host_contactgroups'] = host_contactgroups
    rules['service_contactgroups'] = service_contactgroups

    rules_content = [
        '# Written by Bundlewrap',
        '# encoding: utf-8',
        '',
    ]
    rules_content += generate_rules(rules)

    files['{}/etc/check_mk/conf.d/wato/rules.mk'.format(site_folder)] = {
        'content': '\n'.join(rules_content) + '\n',
        'owner': site,
        'group': site,
        'mode': '0660',
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
            'mode': '0660',
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
            'mode': '0660',
            'needs': [
                'action:check_mk_create_{}_site'.format(site),
            ],
            'triggers': [
                'action:check_mk_recompile_{}_site'.format(site),
            ],
        }

        all_hosts = []
        update_host_tags = []
        extra_host_config_parents = []
        host_attributes = []

        ipaddresses = {}
        snmp_communities = {}

        rediscover_hosts = []
        for host in sorted(folder_config.get('hosts', []), key=sort_hostnames):
            if isinstance(host, str):
                host_node = repo.get_node(host)
                host_node_check_mk_config = host_node.metadata.get('check_mk', {})
                host = {
                    'hostname': host_node.hostname,
                    'port': host_node_check_mk_config.get('port', 6556),
                    'tags': host_node_check_mk_config.get('tags', {}),
                    'attributes': host_node_check_mk_config.get('attributes', {}),
                }

            if host.get('hostname', '') == '':
                continue

            tags = host.get('tags', {})

            # TODO: move this to some metadata processor
            tags.setdefault('site', site)
            tags.setdefault('piggyback', 'auto-piggyback')
            tags.setdefault('networking', 'lan')
            tags.setdefault('snmp_ds', 'no-snmp')
            tags.setdefault('ip-v4', 'ip-v4')
            tags.setdefault('criticality', 'prod')
            tags.setdefault('agent', 'cmk-agent')
            tags.setdefault('address_family', 'ip-v4-only')

            if tags['agent'] in ['cmk-agent', 'snmp-tcp']:
                tags.setdefault('tcp', 'tcp')

            attributes = host.get('attributes', {})
            attributes['meta_data'] = {'created_at': None, 'created_by': None}

            # walk throu all configured site Tags, if they are present in tags, we add them for wato
            for name, tag_config in sorted(site_tags.items(), key=sort_by_prio):
                description = tag_config.get('description', None)
                subtags = tag_config.get('subtags', [])
                # if it is configured, do not change
                if 'tag_{}'.format(name) not in attributes:
                    # TODO: make a sanity check here
                    attributes['tag_{}'.format(name)] = tags.get(name, None)

            all_hosts += ["'" + host['hostname'] + "'", ]

            update_host_tags += [
                "'{hostname}': {host_tags}".format(
                    hostname=host['hostname'],
                    host_tags=sorted_dict(tags),
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
                ipaddresses[host['hostname']] = ip
                attributes['ipaddress'] = ip

            snmp_community = host.get('snmp_community', None)

            if snmp_community:
                snmp_communities[host['hostname']] = snmp_community
                attributes['snmp_community'] = snmp_community

            if attributes:
                host_attributes += [
                    "'{hostname}': {attributes}".format(
                        hostname=host['hostname'],
                        attributes=sorted_dict(attributes),
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

        hosts_content = [
            '# Written by Bundlewrap',
            '# encoding: utf-8',
            '',
            "all_hosts += [" + ', '.join(sorted(all_hosts)) + ']',
            '',
            "host_tags.update({" + ', '.join(update_host_tags) + '})',
            "",
            'host_labels.update({})',
            "",
            ]

        if ipaddresses:
            hosts_content += [
                "# Explicit IPv4 addresses",
                "ipaddresses.update({})".format(ipaddresses),
                '',
            ]

        if snmp_communities:
            hosts_content += [
                "# Explicit SNMP communities",
                "explicit_snmp_communities.update({})".format(snmp_communities),
                '',
            ]

        if extra_host_config_parents:
            hosts_content += [
                                 "",
                                 "# Settings for parents",
                                 "extra_host_conf.setdefault('parents', []).extend([",
                             ] + extra_host_config_parents + ["])", ]

        hosts_content += [
            "# Host attributes (needed for WATO)",
            "host_attributes.update(",
            "{" + ", ".join(host_attributes) + "}",
            ")",
            ]

        files['{}/etc/check_mk/conf.d/wato/{}/hosts.mk'.format(site_folder, folder)] = {
            'content': '\n'.join(hosts_content) + '\n',
            'owner': site,
            'group': site,
            'mode': '0660',
            'needs': [
                'action:check_mk_create_{}_site'.format(site),
            ],
            'triggers': ['action:check_mk_recompile_{}_site'.format(site), ] + ["action:check_mk_rediscover_host_{}".format(host) for host in rediscover_hosts]
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
