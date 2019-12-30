import argparse
import hashlib
import json
import sys
import traceback

import arrow
import snyk

from snyk_threadfix import __version__
from snyk_threadfix.utils import get_token, validate_token

snyk_token = None
client = None
debug = False


class SnykTokenError(Exception):
    pass


class SnykTokenNotFoundError(SnykTokenError):
    pass


class SnykTokenInvalidError(SnykTokenError):
    pass


def log(msg):
    global debug
    if debug:
        print(msg, file=sys.stderr)


def log_error(msg):
    print(msg, file=sys.stderr)


def parse_command_line_args(command_line_args):
    parser = argparse.ArgumentParser(
        description="Generate ThreadFix file format data from Snyk"
    )
    parser.add_argument(
        "--org-id", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--project-ids",
        type=str,
        help="Comma-separated list of Snyk project IDs",
        required=True,
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Optional: name output file to write to (should use .threadfix extension).",
        required=False,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Send additional debug info to stderr",
        required=False,
    )

    args = parser.parse_args(command_line_args)

    str_project_ids = args.project_ids

    if not str_project_ids:
        sys.exit("--project-ids input parameter is required")

    project_ids = str_project_ids.split(",")
    if len(project_ids) > 0:
        args.project_ids = project_ids
    else:
        sys.exit("--project-ids input parameter is required")

    return args


def parse_snyk_project_name(project_name):
    if len(project_name.split(":")) == 1:  # usually for custom-named CLI projects
        return {}

    project_repo_name_and_branch = project_name.split(":")[0]
    project_target_file = project_name.split(":")[1]
    project_repo_name = project_repo_name_and_branch.split("(")[0]

    project_branch_name = None
    if "(" in project_repo_name_and_branch:
        # after the '(' and before the ')'
        project_branch_name = project_repo_name_and_branch.split("(")[1].split(")")[0]

    project_meta_data = {"repo": project_repo_name, "targetFile": project_target_file}

    if project_branch_name:
        project_meta_data["branch"] = project_branch_name

    return project_meta_data


def generate_native_id(org_id, project_id, issue_id, path_list):
    path_str = ">".join(path_list)
    unhashed = "%s:%s:%s:%s" % (org_id, project_id, issue_id, path_str)

    sha1_hash = hashlib.sha1()
    b = bytes(unhashed, "utf-8")
    sha1_hash.update(b)
    hashed_native_id = sha1_hash.hexdigest()

    return hashed_native_id


def snyk_identifiers_to_threadfix_mappings(snyk_identifiers):
    mappings = []
    identifier_keys = snyk_identifiers.keys()

    if "CVE" in identifier_keys:
        cve_identifiers = snyk_identifiers["CVE"]
        is_first_of_type = True
        for i in cve_identifiers:
            mappings.append(
                {"mappingType": "CVE", "value": i, "primary": is_first_of_type}
            )
            is_first_of_type = False

    if "CWE" in identifier_keys:
        cwe_identifiers = snyk_identifiers["CWE"]
        is_first_of_type = True
        for i in cwe_identifiers:
            mappings.append(
                {
                    "mappingType": "CWE",
                    "value": i.replace("CWE-", ""),
                    "primary": is_first_of_type,
                }
            )
            is_first_of_type = False

    other_identifiers = {
        k: v for k, v in snyk_identifiers.items() if k not in ["CVE", "CWE"]
    }
    other_identifier_types = list(other_identifiers.keys())

    # move 'ALTERNATIVE' to the front of the list (so it gets marked primary among TOOL_VENDOR types, if it exists)
    if "ALTERNATIVE" in other_identifier_types:
        other_identifier_types.insert(
            0, other_identifier_types.pop(other_identifier_types.index("ALTERNATIVE"))
        )

    is_first_of_other = True
    for next_identifier_type in other_identifier_types:
        identifiers = other_identifiers[next_identifier_type]
        for i in identifiers:
            mappings.append(
                {
                    "mappingType": "TOOL_VENDOR",
                    "value": str(i),
                    "vendorOtherType": next_identifier_type,
                    "primary": is_first_of_other,
                }
            )
            is_first_of_other = False

    return mappings


git_repo_project_origins = [
    "github",
    "github-enterprise",
    "gitlab",
    "bitbucket-cloud",
    "bitbucket-server",
    "azure-repos",
]


def create_finding_data(
    org_id, snyk_project, snyk_project_metadata, snyk_vulnerability
):
    native_id = generate_native_id(
        org_id, snyk_project.id, snyk_vulnerability.id, snyk_vulnerability.fromPackages
    )

    finding = {
        "nativeId": native_id,
        "severity": snyk_vulnerability.severity,
        "nativeSeverity": snyk_vulnerability.severity,
        "cvssScore": snyk_vulnerability.cvssScore,
        "summary": snyk_vulnerability.title,
        "description": "You can find the description here: %s" % snyk_vulnerability.url,
        "scannerDetail": "You can find the description here: %s"
        % snyk_vulnerability.url,
        "scannerRecommendation": snyk_vulnerability.url,  # TBD
        "dependencyDetails": {
            "library": snyk_vulnerability.package,
            "description": "You can find the description here: %s"
            % snyk_vulnerability.url,
            "reference": snyk_vulnerability.id,
            "referenceLink": "%s#issue-%s"
            % (snyk_project.browseUrl, snyk_vulnerability.id),
            "version": snyk_vulnerability.version,
            "issueType": "VULNERABILITY",
        },
        "metadata": {
            "language": snyk_vulnerability.language,  # TODO: figure out what this means for CLI/container project types
            "packageManager": snyk_vulnerability.packageManager,  # TODO: figure out what this means for CLI/container project types
            "CVSSv3": snyk_vulnerability.CVSSv3,
            "cvssScore": snyk_vulnerability.cvssScore,
            "snyk_source": snyk_project.origin,
            "snyk_project_id": snyk_project.id,
            "snyk_project_name": snyk_project.name,
            "snyk_project_url": snyk_project.browseUrl,
            "snyk_organization": org_id,
        },
        "mappings": [],
    }

    if (
        "repo" in snyk_project_metadata
    ):  # note that these values also makes sense for ECR/ACR/Docker Hub to some degree
        finding["metadata"]["snyk_repo"] = snyk_project_metadata["repo"]
        finding["metadata"]["snyk_target_file"] = snyk_project_metadata["targetFile"]

    if (
        snyk_project.origin in git_repo_project_origins
    ):  # only makes sense for Git Repo sources
        finding["metadata"]["snyk_branch"] = snyk_project_metadata.get(
            "branch", "(default branch)"
        )

    mappings = snyk_identifiers_to_threadfix_mappings(snyk_vulnerability.identifiers)
    finding["mappings"] = mappings

    return finding


def create_threadfix_findings_data(org_id, project_id):
    p = client.organizations.get(org_id).projects.get(project_id)
    findings = []

    project_meta_data = parse_snyk_project_name(p.name)

    for i in p.vulnerabilities:
        finding_data = create_finding_data(org_id, p, project_meta_data, i)
        findings.append(finding_data)

    return findings


def write_to_threadfix_file(output_filename, threadfix_json_obj):
    log("Writing output threadfix file: %s" % output_filename)

    with open(output_filename, "w") as output_json_file:
        json.dump(threadfix_json_obj, output_json_file, indent=4)


def write_output_to_stdout(threadfix_json_obj):
    json.dump(threadfix_json_obj, sys.stdout, indent=4)


def main(args):
    global snyk_token, client, debug
    args = parse_command_line_args(args)
    debug = args.debug

    try:
        snyk_token = get_token()
    except Exception as e:
        log_error(
            "Error fetching Snyk token. Set SNYK_TOKEN env var or run `snyk auth <your-token>` (see https://github.com/snyk/snyk#installation)."
        )
        quit()

    token_is_valid = validate_token(snyk_token)
    if not token_is_valid:
        raise SnykTokenInvalidError("invalid token")

    user_agent_string = "snyk-threadfix/%s" % __version__
    client = snyk.SnykClient(snyk_token, user_agent=user_agent_string)

    project_ids = args.project_ids

    current_time = arrow.utcnow().replace(microsecond=0)
    current_time_str = current_time.isoformat().replace("+00:00", "Z")

    threadfix_json_obj = {
        "created": current_time_str,  # All timestamps are to be in yyyy-MM-dd'T'HH:mm:ss'Z' format
        "exported": current_time_str,  # All timestamps are to be in yyyy-MM-dd'T'HH:mm:ss'Z' format
        "collectionType": "DEPENDENCY",
        "source": "Snyk",
        "findings": [],
    }

    all_threadfix_findings = []

    try:
        for p_id in project_ids:
            threadfix_findings = create_threadfix_findings_data(args.org_id, p_id)
            all_threadfix_findings.extend(threadfix_findings)

        threadfix_json_obj["findings"] = all_threadfix_findings

        if args.output:
            write_to_threadfix_file(args.output, threadfix_json_obj)
        else:
            write_output_to_stdout(threadfix_json_obj)

    except snyk.errors.SnykOrganizationNotFoundError:
        log_error(
            "Error resolving org in Snyk. This is probably because your `--org-id` parameter value is invalid."
        )
        if debug:
            traceback.print_exc(file=sys.stderr)

    except snyk.errors.SnykNotFoundError:
        log_error(
            "Error resolving org / project(s) in Snyk. This is probably your `--org-id` or `--project-ids` parameters contains invalid value(s)."
        )
        if debug:
            traceback.print_exc(file=sys.stderr)


def run():
    args = sys.argv[1:]
    main(args)


if __name__ == "__main__":
    run()
