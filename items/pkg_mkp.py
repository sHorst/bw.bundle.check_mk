from shlex import quote

from bundlewrap.exceptions import BundleError
from bundlewrap.items.pkg import Pkg
from bundlewrap.utils.text import force_text, mark_for_translation as _


class MkpPkg(Pkg):
    """
    A Package installed by Mkp (CheckMk Package).
    """

    BUNDLE_ATTRIBUTE_NAME = "pkg_mkp"
    ITEM_TYPE_NAME = "pkg_mkp"

    ITEM_ATTRIBUTES = {
        'installed': True,
        'url': None,
        'verifySSL': True,
        'hash': None,
    }

    WHEN_CREATING_ATTRIBUTES = {
        'enable_service': True,
    }

    @property
    def pkg_name(self):
        name = self.name

        if '@' in name:
            name = name.split('@', 2)[0]

        if '/' in name:
            name = name.split('/', 1)[1]

        return name

    @property
    def version(self):
        if '@' in self.name:
            return self.name.split('@', 2)[1]
        return None

    @property
    def site(self):
        if '/' in self.name:
            return self.name.split('/', 2)[0]
        return None

    def pkg_all_installed(self):
        result = self.run("su -c '~/bin/mkp list' -l {site} | tail -n +3".format(site=quote(self.site)),
                          may_fail=True)

        for line in result.stdout.decode('utf-8').strip().split("\n"):
            (pkg_name, version) = line.split()[0:2]
            yield f"{self.ITEM_TYPE_NAME}:{self.site}/{pkg_name}@{version}"

    def pkg_install(self):
        quoted_tmp_filename = quote(f'/tmp/{self.site}_{self.pkg_name}_{self.version}.mkp')

        # download package
        self.run("curl -L {verify}-s -o {file} -- {url}".format(
            verify="" if self.attributes.get('verifySSL', True) else "-k ",
            file=quoted_tmp_filename,
            url=quote(self.attributes['url'])
        ))

        # verify Hash only if set
        if self.attributes.get('hash', False):
            if self.node.os == 'macos':
                result = self.run(f"shasum -a 256 -- {quoted_tmp_filename}")
            elif self.node.os in self.node.OS_FAMILY_BSD:
                result = self.run(f"sha256 -q -- {quoted_tmp_filename}")
            else:
                result = self.run(f"sha256sum -- {quoted_tmp_filename}")

            if force_text(result.stdout).strip().split()[0] != self.attributes['hash']:
                # unlink file
                self.run(f"rm -rf -- {quoted_tmp_filename}")

                return False

        # Set owner
        self.run(f'chown {self.site} {quoted_tmp_filename}')

        # install mkp
        self.run(f"su -c '~/bin/mkp add {quoted_tmp_filename}' -l {self.site}", may_fail=True)

        # enable
        if self.when_creating['enable_service']:
            if self.version:
                self.run(f"su -c '~/bin/mkp enable {self.pkg_name} {self.version}' -l {self.site}", may_fail=True)
            else:
                self.run(f"su -c '~/bin/mkp enable {self.pkg_name}' -l {self.site}", may_fail=True)

        # remove tmp file
        self.run(f"rm -rf -- {quoted_tmp_filename}")

    def pkg_installed(self):
        site = quote(self.site)
        pkg_name = quote(self.pkg_name)

        if self.version:
            version = quote(self.version)
            result = self.run(f"su -c '~/bin/mkp list' -l {site} | grep {pkg_name} | grep {version}", may_fail=True)
        else:
            result = self.run(f"su -c '~/bin/mkp list' -l {site} | grep {pkg_name}", may_fail=True)

        return result.return_code == 0 and quote(pkg_name) in result.stdout_text

    def pkg_remove(self):
        if self.version:
            self.run(f"su -c '~/bin/mkp disable {self.pkg_name} {self.version}' -l {self.site}", may_fail=True)
            self.run(f"su -c '~/bin/mkp remove {self.pkg_name} {self.version}' -l {self.site}", may_fail=True)
        else:
            self.run(f"su -c '~/bin/mkp disable {self.pkg_name}' -l {self.site}", may_fail=True)
            self.run(f"su -c '~/bin/mkp remove {self.pkg_name}' -l {self.site}", may_fail=True)

    @staticmethod
    def pkg_in_cache(pkgid, cache):
        pkgtype, pkgname = pkgid.split(":")
        if "@" in pkgname:
            # pkg name contains a version
            return pkgid in cache
        else:
            # ignore version
            for cached_pkgid in cache:
                if cached_pkgid is None:
                    continue
                if cached_pkgid == pkgid or cached_pkgid.startswith(pkgid + "@"):
                    return True
            return False

    def cdict(self):
        cdict = {
            'installed': self.attributes['installed'],
        }
        return cdict

    @classmethod
    def validate_name(cls, bundle, name):
        if "/" not in name:
            raise BundleError(
                f"There is no Site for the pkg_mkp name. "
                f"Please specify the correct site name. "
                f"(pkg_pip:{name} in bundle {bundle.name})"
            )

        site = name.split('/', 2)[0]
        if bundle.node.metadata.get(f'check_mk/sites/{site}', False) is False:
            raise BundleError(
                f"CheckMK Site `{site}` is not defined in (pkg_mkp:{name} in bundle {bundle.name})"
            )

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        super(MkpPkg, cls).validate_attributes(bundle, item_id, attributes)

        # not allowed Attributes for Uninstall
        for str_attr in ['url', 'hash', 'verifySSL']:
            if str_attr in attributes and attributes.get('installed', True) is False:
                raise BundleError(_(f"cannot set {str_attr} for uninstalled "
                                    f"package on {item_id} in bundle '{bundle.name}'"))

        # mandatory Attributes for Install
        for str_attr in ['url']:
            if str_attr not in attributes and attributes.get('installed', True) is True:
                raise BundleError(_(f"must set {str_attr} for installed "
                                    f"package on {item_id} in bundle '{bundle.name}'"))

        # check type
        if not isinstance(attributes.get('when_creating', {}).get('enable_service', True), bool):
            raise BundleError(_(f"expected boolean for 'enable_service' on {item_id} in bundle '{bundle.name}'"))

        for bool_attr in ['verifySSL']:
            if not isinstance(attributes.get(bool_attr, True), bool):
                raise BundleError(_(f"expected boolean for '{bool_attr}' on {item_id} in bundle '{bundle.name}'"))

        for str_attr in ['url', 'hash']:
            if not isinstance(attributes.get(str_attr, ''), str):
                raise BundleError(_(f"expected String for '{str_attr}' on {item_id} in bundle '{bundle.name}'"))

    def get_auto_deps(self, items):
        deps = []
        for item in items:
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name == 'curl':
                deps.append(item.id)

            if item.ITEM_TYPE_NAME == 'action' and item.name == f'check_mk_create_{self.site}_site':
                deps.append(item.id)
        return deps
