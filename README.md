Check MK Server
===============

This Repository contains the bundlewrap bundle for an check_mk server. It will be installed via OMD.

Install
-------
To make this bundle work, you need to insert the items/pkg_mkp.py to the bw repository. This can be done with this command:

```shell
ln -s ../bundles/check_mk/items/pkg_mkp.py items/pkg_mkp.py
```

Dependencies
------------
Packages defined in ```metadata.py``` and installed via [apt-Bundle](https://github.com/sHorst/bw.bundle.apt).

Config
------

General Config:

Since this is for all Servers, I add it to the `all` group

Bundlewrap does not allow for floats in metadata, so there is logic to convert it either by magic, or by string convert

```python
metadata = {
    'check_mk': {
        'users': {
            'stefan': {
                'enabled': True,
                'email': 'stefan@ultrachaos.de',
                'alias': 'Stefan Horst',
                'password': '', # <you password here>,
                'contactgroups': ['all', 'notification'],
                'disable_notifications': False,
                'notification_rules': {
                    'push_over': {
                        'type': 'pushover',
                        'match_host_event': ['rd', 'dr', 'x'],
                        'match_service_event': ['rc', 'wc', 'cr', 'uc', 'f', 's', 'x'],
                        'api_key': 'YOUR API KEY HERE',
                        'recipient_key': 'YOUR RECIPIENT_KEY HERE', 
                    }
                },
            },
        },
        'aux_tags': {
            # Example Tags, for filtering Services later
            'http': {
                'topic': 'Services',
                'title': 'HTTP Server',
            },
        },
        'host_tags': {
            # Default Check_mk Host Tags, needs to be here as well, so they can be added correctly
            'agent': {
                'notInTagConfig': True,
                'title': 'Agent type',
                'subtags': {
                    'cmk-agent': ('Check_MK Agent (Server)', ['tcp']),
                    'snmp-only': ('SNMP (Networking device, Appliance)', ['snmp']),
                    'snmp-v1': ('Legacy SNMP device (using V1)', ['snmp']),
                    'snmp-tcp': ('Dual: Check_MK Agent + SNMP', ['snmp', 'tcp']),
                    'no-agent': ('No Agent', ['ping']),
                },
            },
            'snmp_ds': {
                'notInTagConfig': True,
                'title': 'SNMP',
                'subtags': {
                    'no-snmp': ('No SNMP', []),
                    'snmp-v1': ('SNMP v1', ['snmp']),
                    'snmp-v2': ('SNMP v2 or v3', ['snmp', 'snmp-tcp']),
                },
            },

            'criticality': {
                'title': 'Criticality',
                'subtags': {
                    'prod': ('Productive system', []),
                    'critical': ('Business critical', []),
                    'test': ('Test system', []),
                    'offline': ('Do not monitor this host', []),
                },
            },

            'networking': {
                'topic': 'Unknown',
                'title': 'Networking Segment',
                'subtags': {
                    'lan': ('Local network (low latency)', []),
                    'wan': ('WAN (high latency)', []),
                    'dmz': ('DMZ (low latency, secure access)', []),
                },
            },

            # Tag for filtering by distro, can be extended
            'dist': {
                'title': 'Distribution',
                'subtags': {
                    'None': ('Not Set', []),
                    'deb': ('Debian', []),
                    'suse': ('Suse', []),
                    'wrt': ('WRT', []),
                    'mikrotik': ('MikroTik', []),
                    'netgear': ('Netgear', []),
                    'vmware': ('VMWare', []),
                    'netapp': ('NetApp', []),
                },
            },

            'web': {
                'topic': 'Services',
                'title': 'Web Server',
                'subtags': {
                    'None': ('Nein', []),
                    'http_': ('HTTP only', ['http']),
                    'httpPlus': ('HTTP/S', ['http', 'https']),
                    'https_': ('HTTPs only', ['https']),
                },
            },
        },
        
        # group hosts by tags
        'host_groups': {
            'debian-servers': {
                'description': 'Debian Server',
                'id': '5cc0ce49-0565-402a-bd5a-c30ded9a0116',
                'condition': {'host_tags': {'dist': 'deb'}},
            },
            'http-servers': {
                'description': 'Web Server',
                'id': 'c3b095b2-33cb-48fc-ae9f-6804646d88b0',
                'condition': {'host_tags': {'http': 'http'}},
            },
            'mikrotik-switche': {
                'description': 'MikroTik Switche',
                'id': '4115f0c8-93ad-444d-8420-a1a8139a4f32',
                'condition': {'host_tags': {'dist': 'mikrotik'}},
            },
            'netgear-switche': {
                'description': 'Netgear Switche',
                'id': '40b3a416-3492-48f7-a382-86c9ffe58736',
                'condition': {'host_tags': {'dist': 'netgear'}},
            },
            'suse-servers': {
                'description': 'Suse Server',
                'id': '5130ece6-fedc-4e65-800b-e7907647fd51',
                'condition': {'host_tags': {'dist': 'suse'}},
            },
            'vmware-servers': {
                'description': 'VMWare Server',
                'id': 'b1fdc810-bf3c-4470-adb5-b2fa7b4d65be',
                'condition': {'host_tags': {'dist': 'vmware'}},
            },
        },
        
        # configure Contact Groups
        'contact_groups': {
            'notification': {
                'description': 'Notification',

                'hosts': {
                    'description': 'Admin Notification',
                    'id': '8177b6cc-3e63-4d75-97d5-5d9eda649bf8',
                },
                'services': {
                    'description': 'Admin Notification',
                    'id': 'fcb8a6ca-30e0-4cf0-8278-904e2b0c7572',
                },
            },
        },
        
        
        'global_rules': {
            'extra_host_conf': {
                # configure all hosts to send notifications
                'notification_options': [
                    {
                        'condition': {},
                        'id': '59748d3a-7ee9-4d97-adfc-873ffe365d1a',
                        'value': 'd,r,f,s'
                    },
                ],
                'first_notification_delay': [
                    {'condition': {},
                     'id': 'cd7acb33-d055-4472-8f14-e29864c05325',
                     'options': {'description': 'notifications after 5 min'},
                     'value': '5.0'},
                ],
                
                # add icons for distro tags
                'icon_image': [
                    {'condition': {'host_tags': {'dist': 'deb'}},
                     'id': '783daab3-a540-4a30-a56b-bcd7cc24464c',
                     'options': {'description': 'Debian Server'},
                     'value': 'debian'},
                    {'condition': {'host_tags': {'dist': 'mikrotik'}},
                     'id': '98d28eaf-fd13-4bdd-8437-595c07d846b5',
                     'options': {'description': 'MikroTik Switche'},
                     'value': 'mikrotik'},
                    {'condition': {'host_tags': {'dist': 'netgear'}},
                     'id': 'dac7e67c-081e-448d-9803-9b449a4431f9',
                     'options': {'description': 'Netgear Switche'},
                     'value': 'netgear'},
                    {'condition': {'host_tags': {'dist': 'vmware'}},
                     'id': 'd1750f48-ac99-4faa-811a-6548210a2a06',
                     'options': {'description': 'VMWare Server'},
                     'value': 'vmware2'},
                ],
            },
            
            'extra_service_conf': {
                'check_interval': [
                    {
                        'condition': {'service_description': [{'$regex': 'Check_MK HW/SW Inventory'}]},
                        'id': 'fe72f191-47e1-450a-832f-02e1d34204ff',
                        'options': {'description': u'Restrict HW/SW-Inventory to once a day'},
                        'value': "1440.0",
                    },
                ],
                
                'max_check_attempts': [
                    {
                        'condition': {},
                        'id': '68a15bae-e137-4c68-85b4-4ad63e58e4eb',
                        'options': {'description': 'set max check attempts to 4'},
                        'value': 4
                    },
                    {
                        'condition': {'service_description': [{'$regex': 'NTP Time'}]},
                        'id': '8853631d-68e3-4c2b-bca1-5086d0dd634c',
                        'options': {'description': 'NTP 8 Times'},
                        'value': 8
                    },
                ],
                
                'first_notification_delay': [
                    {
                        'condition': {},
                        'id': 'aabd6a67-117e-4b20-9f5a-2ebaa4a6b520',
                        'options': {'description': 'Delay notifications for 5 min'},
                        'value': '5.0',  # will be converted to float
                    },
                ],
            },
            
            'active_checks': {
                'cmk_inv': [
                    {
                        'condition': {'host_tags': {'dist': 'vmware'}},
                        'id': '0454bf9b-e1b4-47aa-91de-68db18938211',
                        'options': {'description': 'Inventory of ESX'},
                        'value': {}
                    },
                ]
            },
            
            'custom_checks': [
                # Add custom nagios checks
                {'condition': {'host_tags': {'tag': 'tag 123'}},
                 'id': '9feef913-a912-4cda-98aa-748f865ad7bd',
                 'options': {'description': u'Custom Check'},
                 'value': {'command_line': '$USER4$/custom_checks/custom_check.pl '
                                           '-H $HOSTALIAS$ -M cpu -w 100000000 -c 150000000',
                           'service_description': 'custom Check'}},
            ],

            # Config can also be included as string only, this will be copied as is
            'ignored_services': [
                "{'condition': {'host_tags': {'noPing': 'noping'},\n"
                "               'service_description': [{'$regex': 'PING'}]},\n"
                " 'id': '650b8a21-9cbd-44b2-82f4-95f70fb80020',\n"
                " 'options': {'comment': 'Do not use ping if host is no ping',\n"
                "             'description': 'Ignore Ping'},\n"
                " 'value': True}"

            ],

            'special_agents': {
                'vsphere': [
                    {'condition': {'host_tags': {'dist': 'vmware'}},
                     'id': '8e50b588-9a0a-42b5-91b0-ae42fb3dc44d',
                     'options': {'description': 'ESX vSphere'},
                     'value': {'direct': True,
                               'infos': ['hostsystem',
                                         'virtualmachine',
                                         'datastore',
                                         'counters',
                                         'licenses'],
                               'secret': ('password', 'ENTER PASSWORD HERE!!'),
                               'skip_placeholder_vms': True,
                               'snapshots_on_host': False,
                               'spaces': 'cut',
                               'ssl': False,
                               'user': 'check_mk'}}
                ],
                'netapp': [
                    {
                        'condition':
                            {
                                'host_tags': {'dist': 'netapp'}
                            },
                        'id': '595cfbe1-81d6-4abe-8b5f-ebaa538bc66d',
                        'options': {'description': 'netapp', 'disabled': False, },
                        'value': {
                            'password': ('password', 'ENTER PASSWORD HERE!!'),
                            'skip_elements': [],
                            'username': 'check_mk2',  # netapp uses SNMP username as well, so this is a second user 
                        }
                    }
                ],
            },

            'checkgroup_parameters': {
                "mysql_sessions": [
                    {'condition': {'host_tags': {'mysql': 'mysql'}},
                     'id': 'b77b487a-7303-432c-8681-36f8cb3b98df',
                     'options': {'description': 'Mysql Process'},
                     'value': {'connections': [20, 40], 'running': [10, 20], 'total': [100, 200]}},
                ],
                "netapp_disks": [
                    {'condition': {'host_tags': {'dist': 'netapp'}},
                     'id': '2afc7c03-eb1e-4a0a-b421-70c9a4469fc8',
                     'options': {'description': 'netapp disk levels'},
                     'value': {}},
                ],
                "netapp_luns": [
                    {'condition': {'host_tags': {'dist': 'netapp'}},
                     'id': '51dee786-2b96-4708-8eca-7ef59c91b1e9',
                     'options': {'description': 'netapp luns'},
                     'value': {}},
                ],
            },
            'host_check_commands': [
                {'condition': {'host_tags': {'noPing': 'noping'}},
                 'id': 'f9f6c2bd-da36-441f-a182-f512adcb8f76',
                 'options': {'description': 'NoPing'},
                 'value': 'agent'}
            ],
            'bulkwalk_hosts': [
                {'condition': {'host_tags': {'snmp': 'snmp', 'snmp_ds': {'$ne': 'snmp-v1'}}},
                 'id': '2c243a09-7dbe-48f8-96f6-32b4cdec8d71',
                 'options': {'description': u'Hosts with the tag \"snmp-v1\" must not use bulkwalk'},
                 'value': True},
            ],
            'only_hosts': [
                {'condition': {'host_tags': {'criticality': {'$ne': 'offline'}}},
                 'id': 'b57119af-a91a-4c6a-aaae-e163b91dbcb8',
                 'options': {'description': 'Do not monitor hosts with the tag \"offline\"'},
                 'value': True}
            ],
            
            'periodic_discovery': [
                {
                    'condition': {},
                    'id': '6bceed53-6ee2-4b0d-8bdf-839f9f71f2e9',
                    'options': {'description': 'Perform every two hours a service discovery'},
                    'value': {
                        'check_interval': '%#%FLOAT(120.0)%#%',  # will be convertet to a Float
                        'inventory_check_do_scan': True,
                        'severity_new_host_label': 1,  # New since 2.1
                        'severity_unmonitored': 1,
                        'severity_vanished': 0
                    }
                }
            ],
            
            'ping_levels': [
                {'condition': {'host_tags': {'networking': 'wan'}},
                 'id': '7d670f77-1d6a-4c89-b4fe-e9fb7a9214d2',
                 'options': {'description': 'Allow longer round trip times when pinging WAN '
                                            'hosts'},
                 'value': {'loss': ('%#%FLOAT(80.0)%#%', '%#%FLOAT(100.0)%#%'),
                           'packets': 6,
                           'rta': ('%#%FLOAT(1500.0)%#%', '%#%FLOAT(3000.0)%#%'),
                           'timeout': 20}}
            ],
        },
    },
}
```

Individual Server Config:
```python
metadata = {
    'check_mk': {
        'version': '2.2.0p4',  # default Version
        'sites': {
            'site1': {
                'admin_email': 'stefan@example.com',
                'url': 'https://monitoring.example.com',
                'livestatus': True,
                'admins': ['stefan', ],
                
                # install this Packages from the CheckMK Exchange
                'add_packages': {
                    'apcaccess': {
                        'version': '5.2.1',
                        'url': 'https://exchange.checkmk.com/packages/apcaccess/1105/apcaccess-5.2.1.mkp',
                        'hash': '1d0d1a31429c48fd251395969bc4c96dcd6291c4c8c61165666340213fe10711',
                    },
                },

                'locked_config': False,  # wether or not add the _locked = True flag to configs

                # Wato folders
                'folders': {
                    'brannigan': {
                        'generated': True,  # generate group from Bundlewrap Group
                        'group': 'aac-01.brannigan',  # group Name to use
                        'hosts': [],  # no additional hosts, only generated
                    },
                    'check_mk': {
                        'generated': True, 
                        'bundle': 'check_mk',  # generate by bundle, this will add all check_mk Servers
                        'include_self': True,  # even ourself
                        'hosts': [],
                    },
                    'not_generated': {
                        # add custom rules only for this folder
                        'rules': { 
                            'checkgroup_parameters': {
                                'esx_host_memory': [
                                    {
                                        'condition': {'host_folder': '%#%FOLDER_PATH%#%',  # '/%s/' % FOLDER_PATH,
                                                      # Attatch to special hosts
                                                      'host_name': [
                                                          'esx1',
                                                      ]
                                                      },
                                        'id': 'bac8ebcb-a5b1-4460-a10e-0f1dda563df4',
                                        'options': {'description': 'more critical', 'disabled': False, },
                                        'value': {
                                            'levels_upper': ('%#%FLOAT(80.0)%#%', '%#%FLOAT(95.0)%#%'),
                                        },
                                    }
                                ],
                                'ipmi': [
                                    {'condition': {'host_folder': '%#%FOLDER_PATH%#%',  # '/%s/' % FOLDER_PATH,
                                                   'host_name': [
                                                       'esx1',
                                                   ],
                                                   'service_description': [{'$regex': 'Fan'}]},
                                     'id': '3330e690-f8ff-4bc1-8b28-433a9b14d747',
                                     'options': {'description': 'Fan min'},
                                     'value': {'numerical_sensor_levels': [('Fan_1', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_2', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_3', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_4', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_5', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_6', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_7', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_8', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')}),
                                                                           ('Fan_9', {'lower': ('%#%FLOAT(10.0)%#%', '%#%FLOAT(0.0)%#%')})],
                                               'sensor_states': [('lower non-critical threshold', 0)]}},
                                ],
                            },
                            'ignored_services': [
                                {'condition': {'host_folder': '%#%FOLDER_PATH%#%',  # '/%s/' % FOLDER_PATH,
                                               'host_name': [
                                                   'esx1',
                                               ],
                                               'service_description': [
                                                   {'$regex': 'VM .*$'},
                                               ]},
                                 'id': '8fcc8c86-ccef-4e06-a903-be70fc96d354',
                                 'value': True},

                                {'condition': {'host_folder': '%#%FOLDER_PATH%#%',  # '/%s/' % FOLDER_PATH,
                                               'host_name': [
                                                   'esx1',
                                               ],
                                               'service_description': [
                                                   {'$regex': 'Management Interface: IPMI Sensor UID_Light$', },
                                                   {'$regex': 'Management Interface: IPMI Sensor UID$', },
                                                   {'$regex': 'Management Interface: IPMI Sensor Sys_Health_LED$', },
                                               ]},
                                 'id': '8b8c8f88-9e2b-4c59-ba82-9cb1fabfb858',
                                 'options': {'description': u'disable impi uid'},
                                 'value': True},
                            ],
                        },
                        'hosts': [  # manually add Servers here
                            {
                                'hostname': 'server1.example.com',
                                'tags': {
                                    'ssh': 'ssh',
                                    'https': 'https',
                                    'dist': 'deb',
                                },
                                'ip_address': '192.168.x.x',
                                'management_address': '192.168.x.x',  # if available, otherwise can be left out
                                'management_ipmi_credentials': {
                                    'username': 'check_mk',  # or the one you choose
                                    'password': 'PASSWORD HERE', 
                                },
                            },
                            {
                                'hostname': 'ping_only',
                                'tags': {
                                    'agent': 'no-agent',
                                    'dist': 'cisco',
                                    'ping': 'ping',
                                },
                                'ip_address': 'x.x.x.x',

                            },
                            {
                                'hostname': 'esx1',
                                'tags': {
                                    'dist': 'vmware',
                                },
                                'ip_address': '192.168.x.x',
                                'management_address': '192.168.x.x',
                                'management_ipmi_credentials': {
                                    'username': 'check_mk',  # or the one you choose
                                    'password': 'PASSWORD HERE',
                                },
                            },
                            {
                                'hostname': 'snmp_switch',
                                'tags': {
                                    'agent': 'special-agents',
                                    'snmp_ds': 'snmp-v1',
                                    'snmp': 'snmp',
                                    'dist': 'netgear',
                                },
                                'ip_address': '192.168.x.x',
                                'snmp_community': 'monitor',
                            },
                        ],
                    },
                }
            },
        },
    },
}
```


Enable Check_mk user
---

netapp < 9.3:
```shell
useradmin role add check_mk -c "check_mk readonly account" -a login-http-admin,api-perf-object-get-instances*,api-net-ifconfig-get,api-aggr-list-info,api-storage-shelf-bay-list-info,api-disk-list-info,api-vfiler-list-info,api-vfiler-get-status,api-volume-list-info,api-system-get-version,api-system-get-info,api-storage-shelf-environment-list-info,api-cf-status,api-diagnosis-status-get,api-license-list-info,api-snapvault-secondary-relationship-status-list-iter-start,api-snapmirror-get-status,api-quota-report
useradmin group add check_mk_group -c "check_mk readonly" -r check_mk
useradmin user add check_mk -c "check_mk readonly" -g check_mk_group
```

netapp > 9.3:
```shell
security login create -user-or-group-name check_mk2 -application console -role readonly -authentication-method password 
security login create -user-or-group-name check_mk2 -application http -role readonly -authentication-method password    
security login create -user-or-group-name check_mk2 -application ontapi -role readonly -authentication-method password 
security login create -user-or-group-name check_mk2 -application ssh -role readonly -authentication-method password  
```
