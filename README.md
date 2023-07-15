Check MK Server
===============

This Repository contains the bundlewrap bundle for an check_mk server. It will be installed via OMD.

Config
------

TBD

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
