"""
Update ReadTheDocs to show and hide releases.
"""

import re
import sys

from session import get_session

# How many from each level to show.
NUM_MAJORS = 3
NUM_MINORS = 3
OLD_MINORS = 1
NUM_MICROS = 1
OLD_MICROS = 1


def get_all_versions(project):
    """Pull all the versions for a project from ReadTheDocs."""
    versions = []
    session = get_session("RTFD_TOKEN")

    url = f"https://readthedocs.org/api/v3/projects/{project}/versions/"
    while url:
        resp = session.get(url)
        resp.raise_for_status()
        data = resp.json()
        versions.extend(data["results"])
        url = data["next"]
    return versions


def version_tuple(vstr):
    """Convert a tag name into a version_info tuple."""
    m = re.fullmatch(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?(?:([abc])(\d+))?", vstr)
    if not m:
        return None
    return (
        int(m[1]),
        int(m[2]),
        int(m[3] or 0),
        (m[4] or "final"),
        int(m[5] or 0),
    )


def main(project):
    """Update ReadTheDocs for the versions we want to show."""

    # Get all the tags. Where there are dupes, keep the shorter tag for a version.
    versions = get_all_versions(project)
    versions.sort(key=(lambda v: len(v["verbose_name"])), reverse=True)
    vdict = {}
    for v in versions:
        if v["type"] == "tag":
            vinfo = version_tuple(v["verbose_name"])
            if vinfo and vinfo[3] == "final":
                vdict[vinfo] = v

    # Decide which to show and update them.

    majors = set()
    minors = set()
    micros = set()
    minors_to_show = NUM_MINORS
    micros_to_show = NUM_MICROS

    session = get_session("RTFD_TOKEN")
    version_list = sorted(vdict.items(), reverse=True)
    for vi, ver in version_list:
        if vi[:1] not in majors:
            majors.add(vi[:1])
            minors = set()
            if len(majors) > 1:
                minors_to_show = OLD_MINORS
                micros_to_show = OLD_MICROS
        if vi[:2] not in minors:
            minors.add(vi[:2])
            micros = set()
        if vi[:3] not in micros:
            micros.add(vi[:3])

        show_it = (
            len(majors) <= NUM_MAJORS
            and len(minors) <= minors_to_show
            and len(micros) <= micros_to_show
        )
        active = ver["active"] or (len(majors) <= NUM_MAJORS)
        hidden = not show_it

        update = ver["active"] != active or ver["hidden"] != hidden
        if update:
            print(f"Updating {ver['verbose_name']} to {active=}, {hidden=}")
            url = ver["_links"]["_self"]
            resp = session.patch(url, data={"active": active, "hidden": hidden})
            resp.raise_for_status()

    # Set the default version.
    latest = version_list[0][1]
    print(f"Setting default version to {latest['slug']}")
    url = latest["_links"]["project"]
    resp = session.patch(url, data={"default_version": latest["slug"]})
    resp.raise_for_status()


if __name__ == "__main__":
    main(sys.argv[1])
