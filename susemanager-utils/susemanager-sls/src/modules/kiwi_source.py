#  pylint: disable=missing-module-docstring

# SPDX-FileCopyrightText: 2018-2025 SUSE LLC
#
# SPDX-License-Identifier: Apache-2.0

import salt.exceptions
import logging
import os

# pylint: disable-next=unused-import
from tempfile import mkdtemp

try:
    # pylint: disable-next=unused-import
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

log = logging.getLogger(__name__)

# valid prefixes taken from Docker-CE to be compatible
valid_git_prefixes = ["http://", "https://", "git://", "github.com/", "git@"]
valid_url_prefixes = ["http://", "https://"]
valid_url_suffixes = [".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".tar"]


# pylint: disable-next=invalid-name
def _isLocal(source):
    # pylint: disable-next=undefined-variable
    return __salt__["file.directory_exists"](source)


# pylint: disable-next=invalid-name
def _isGit(source):
    for prefix in valid_git_prefixes:
        if source.startswith(prefix):
            return True
    return False


# pylint: disable-next=invalid-name
def _isTarball(source):
    prefix_ok = False
    for prefix in valid_url_prefixes:
        if source.startswith(prefix):
            prefix_ok = True
            break

    if not prefix_ok:
        return False

    for suffix in valid_url_suffixes:
        if source.endswith(suffix):
            return True

    return False


# pylint: disable-next=invalid-name
def _prepareDestDir(dest):
    """
    Check target directory does not exists
    """
    if os.path.isdir(dest):
        raise salt.exceptions.SaltException(
            # pylint: disable-next=consider-using-f-string
            'Working directory "{0}" exists before sources are prepared'.format(dest)
        )


# pylint: disable-next=invalid-name
def _prepareLocal(source, dest):
    """
    Make link from `source` to `dest`
    """
    log.debug("Source is local directory")
    _prepareDestDir(dest)
    # pylint: disable-next=undefined-variable
    __salt__["file.symlink"](source, dest)
    return dest


# pylint: disable-next=invalid-name
def _prepareHTTP(source, dest):
    """
    Download tarball and extract to the directory
    """
    log.debug("Source is HTTP")
    _prepareDestDir(dest)

    filename = os.path.join(dest, source.split("/")[-1])
    # pylint: disable-next=undefined-variable
    res = __salt__["state.single"](
        "file.managed", filename, source=source, makedirs=True, skip_verify=True
    )
    # pylint: disable-next=unused-variable
    for s, r in list(res.items()):
        if not r["result"]:
            raise salt.exceptions.SaltException(r["comment"])
    # pylint: disable-next=undefined-variable
    res = __salt__["state.single"](
        "archive.extracted",
        name=dest,
        source=filename,
        skip_verify=True,
        overwrite=True,
    )
    for s, r in list(res.items()):
        if not r["result"]:
            raise salt.exceptions.SaltException(r["comment"])
    return dest


# pylint: disable-next=invalid-name
def _prepareGit(source, dest, root):
    _prepareDestDir(dest)

    # checkout git into temporary directory in our build root
    # this is needed if we are interested only in git subtree
    # pylint: disable-next=undefined-variable
    tmpdir = __salt__["temp.dir"](parent=root)

    rev = "master"
    subdir = None
    url = None

    # parse git uri - i.e. git@github.com/repo/#rev:sub
    # compatible with docker as per https://docs.docker.com/engine/reference/commandline/build/#git-repositories

    try:
        url, fragment = source.split("#", 1)
        try:
            rev, subdir = fragment.split(":", 1)
        # pylint: disable-next=bare-except
        except:
            rev = fragment
    # pylint: disable-next=bare-except
    except:
        url = source

    # omitted rev means default 'master' branch revision
    if rev == "":
        rev = "master"

    # pylint: disable-next=logging-format-interpolation,consider-using-f-string
    log.debug("GIT URL: {0}, Revision: {1}, subdir: {2}".format(url, rev, subdir))
    # pylint: disable-next=undefined-variable
    __salt__["git.init"](tmpdir)
    # pylint: disable-next=undefined-variable
    __salt__["git.remote_set"](tmpdir, url)
    # pylint: disable-next=undefined-variable
    __salt__["git.fetch"](tmpdir)
    # pylint: disable-next=undefined-variable
    __salt__["git.checkout"](tmpdir, rev=rev)

    if subdir:
        if _isLocal(os.path.join(tmpdir, subdir)):
            # pylint: disable-next=undefined-variable
            __salt__["file.symlink"](os.path.join(tmpdir, subdir), dest)
        else:
            raise salt.exceptions.SaltException(
                # pylint: disable-next=consider-using-f-string
                "Directory is not present in checked out source: {}".format(subdir)
            )
    else:
        # pylint: disable-next=undefined-variable
        __salt__["file.symlink"](tmpdir, dest)
    return dest


def prepare_source(source, root):
    """
    Prepare source directory based on different source types.

    source -- string with either local directory path, remote http(s) archive or git repository
    root   -- local directory where to store processed source files

    For git repository following format is understood:
      [http[s]://|git://][user@]hostname/repository[#revision[:subdirectory]]
    """
    dest = os.path.join(root, "source")
    # pylint: disable-next=logging-format-interpolation,consider-using-f-string
    log.debug("Preparing build source for {0} to {1}".format(source, dest))
    if _isLocal(source):
        return _prepareLocal(source, dest)
    elif _isTarball(source):
        return _prepareHTTP(source, dest)
    elif _isGit(source):
        return _prepareGit(source, dest, root)
    else:
        raise salt.exceptions.SaltException(
            # pylint: disable-next=consider-using-f-string
            'Unknown source format "{0}"'.format(source)
        )
