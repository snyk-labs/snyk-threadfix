import sys
import argparse
import json
import snyk
import hashlib
import arrow
from utils import get_token, get_default_token_path, get_snyk_api_headers, validate_token

snyk_token = None
client = None


def parse_command_line_args(command_line_args):
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--repoName", type=str, help="Repo name", required=True
    )
    parser.add_argument(
        "--branch", type=str, help="Branch name", required=False
    )
    parser.add_argument(
        "--targetFile", type=str, help="Target file (ex package.json, Dockerfile, etc", required=False
    )
    parser.add_argument(
        "--origin", type=str, help="Origin - ex github, bitbucket-server, cli, etc", required=False
    )
    return parser.parse_args(command_line_args)


def parse_snyk_project_name(project_name):
    project_repo_name_and_branch = project_name.split(':')[0]
    project_target_file = project_name.split(':')[1]
    project_repo_name = project_repo_name_and_branch.split('(')[0]

    # after the '(' and before the ')'
    project_branch_name = project_repo_name_and_branch.split('(')[1].split(')')[0]

    return {
        'repo': project_repo_name,
        'branch': project_branch_name,
        'targetFile': project_target_file
    }


def lookup_project_ids_by_repo_name_py_snyk(org_id, repo_name, origin, branch, target_file):
    projects = client.organizations.get(org_id).projects.all()

    matching_project_ids = []

    for p in projects:
        if p.origin in ['ecr', 'acr', 'docker-hub']:
            print('found container image project')

        elif p.origin == 'cli':
            print('found CLI project')

        else:
            project_name_details = parse_snyk_project_name(p.name)

            if repo_name == project_name_details['repo'] and \
                    (not branch or branch and branch == project_name_details['branch']) and \
                    (not origin or origin and origin == p.origin) and \
                    (not target_file or target_file and target_file == project_name_details['targetFile']):
                print('found regular project')
                print(p.name)
                print(p.id)
                print(p.origin)
                print()

                matching_project_ids.append(p.id)

    return matching_project_ids


def generate_native_id(org_id, project_id, issue_id, path_list):
    path_str = '>'.join(path_list)
    unhashed = '%s:%s:%s:%s' % (org_id, project_id, issue_id, path_str)

    sha1_hash = hashlib.sha1()
    b = bytes(unhashed, 'utf-8')
    sha1_hash.update(b)
    hashed_native_id = sha1_hash.hexdigest()

    return hashed_native_id


def snyk_identifiers_to_threadfix_mappings(snyk_identifiers_list):
    mappings = []

    identifier_keys = snyk_identifiers_list.keys()
    primary_key = ''
    primary_set = False

    if 'CWE' in identifier_keys and snyk_identifiers_list['CWE']:
        primary_key = 'CWE'
    elif 'ALTERNATIVE' in identifier_keys and snyk_identifiers_list['ALTERNATIVE']:
        primary_key = 'ALTERNATIVE'
    elif 'CVE' in identifier_keys and snyk_identifiers_list['CVE']:
        primary_key = 'CVE'
    elif 'NSP' in identifier_keys and snyk_identifiers_list['NSP']:
        primary_key = 'NSP'

    for k, v_list in snyk_identifiers_list.items():
        if v_list:
            for v in v_list:
                is_primary = False
                if k == primary_key and not primary_set:
                    is_primary = True
                    primary_set = True

                mapping_value = v.replace("CWE-", "") if k == 'CWE' else v

                mappings.append({
                    "mappingType": k,
                    "value": mapping_value,
                    "primary": is_primary
                })

    return mappings


def create_threadfix_findings_data(org_id, project_id):
    p = client.organizations.get(org_id).projects.get(project_id)
    findings = []
    target_file = parse_snyk_project_name(p.name)['targetFile']

    for i in p.vulnerabilities:
        native_id = generate_native_id(org_id, project_id, i.id, i.fromPackages)

        finding = {
            'nativeId': native_id,
            'severity': i.severity,
            'nativeSeverity': i.cvssScore,
            'summary': i.title,
            'description': 'You can find the description here: %s' % i.url,
            'scannerDetail': 'You can find the description here: %s' % i.url,
            'scannerRecommendation': i.url,  # TBD
            'dependencyDetails': {
                'library': i.package,
                'description': 'You can find the description here: %s' % i.url,
                'reference': i.id,
                'referenceLink': i.url,
                'filePath': target_file,
                'version': i.version,
                'issueType': 'VULNERABILITY',
            },
            'metadata': {
                "language": i.language,  # TODO: figure out what this means for CLI/container project types
                "packageManager": i.packageManager,  # TODO: figure out what this means for CLI/container project types
                "CVSSv3": i.CVSSv3,
                "cvssScore": i.cvssScore,
                "snyk_source": p.origin,
                "snyk_project_url": p.browseUrl,
                "snyk_organization": org_id
            },

            'mappings': []
        }

        mappings = snyk_identifiers_to_threadfix_mappings(i.identifiers)
        finding['mappings'] = mappings
        findings.append(finding)

    return findings


def write_to_threadfix_file(output_filename, threadfix_json_obj):
    with open(output_filename, 'w') as output_json_file:
        print(json.dump(threadfix_json_obj, output_json_file, indent=4))


def main(args):
    args = parse_command_line_args(args)

    repo_name = args.repoName
    branch = args.branch or ''
    target_file = args.targetFile or ''
    origin = args.origin or ''

    snyk_token_path = get_default_token_path()
    global snyk_token, client
    snyk_token = get_token(snyk_token_path)
    token_is_valid = validate_token(snyk_token)
    if not token_is_valid:
        print('invalid token')
        sys.exit('invalid token')

    client = snyk.SnykClient(snyk_token)

    project_ids = lookup_project_ids_by_repo_name_py_snyk(args.orgId, repo_name, origin, branch, target_file)
    print(project_ids)

    current_time = arrow.utcnow().replace(microsecond=0)
    current_time_str = current_time.isoformat().replace("+00:00", "Z")

    threadfix_json_obj = {
        'created': current_time_str,  # All timestamps are to be in yyyy-MM-dd'T'HH:mm:ss'Z' format
        'exported': current_time_str,  # All timestamps are to be in yyyy-MM-dd'T'HH:mm:ss'Z' format
        'collectionType': 'DEPENDENCY',
        'source': 'Snyk',
        'findings': []
    }

    all_threadfix_findings = []

    for p_id in project_ids:
        threadfix_findings = create_threadfix_findings_data(args.orgId, p_id)
        all_threadfix_findings.extend(threadfix_findings)

    threadfix_json_obj['findings'] = all_threadfix_findings

    output_filename = 'snyk-threadfix-%s.threadfix' % current_time_str.replace(':', '.')
    write_to_threadfix_file(output_filename, threadfix_json_obj)

    print('done')


if __name__ == '__main__':
    args = sys.argv[1:]
    main(args)
