import os

import pytest
import snyk
import tomlkit
from mock import patch

from snyk_threadfix import __version__, main


def test_snyk_identifiers_to_threadfix_mapping_with_mpultiple_cwes_and_alternative():
    snyk_identifiers = {
        "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
        "CWE": ["CWE-185", "CWE-400"],
        "ALTERNATIVE": ["SNYK-JS-BRACES-10900"],
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]["mappingType"] == "CVE"
    assert mapping[0]["value"] == "CVE-2019-11358"
    assert mapping[0]["primary"] is True

    assert mapping[1]["mappingType"] == "CVE"
    assert mapping[1]["value"] == "CVE-2019-5428"
    assert mapping[1]["primary"] is False

    assert mapping[2]["mappingType"] == "CWE"
    assert mapping[2]["value"] == "185"
    assert mapping[2]["primary"] is True

    assert mapping[3]["mappingType"] == "CWE"
    assert mapping[3]["value"] == "400"
    assert mapping[3]["primary"] is False

    assert mapping[4]["mappingType"] == "TOOL_VENDOR"
    assert mapping[4]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[4]["value"] == "SNYK-JS-BRACES-10900"
    assert mapping[4]["primary"] is True


def test_snyk_identifiers_to_threadfix_mapping_with_nsp():
    snyk_identifiers = {
        "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
        "CWE": ["CWE-400"],
        "NSP": [796],
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]["mappingType"] == "CVE"
    assert mapping[0]["value"] == "CVE-2019-11358"
    assert mapping[0]["primary"] is True

    assert mapping[1]["mappingType"] == "CVE"
    assert mapping[1]["value"] == "CVE-2019-5428"
    assert mapping[1]["primary"] is False

    assert mapping[2]["mappingType"] == "CWE"
    assert mapping[2]["value"] == "400"
    assert mapping[2]["primary"] is True

    assert mapping[3]["mappingType"] == "TOOL_VENDOR"
    assert mapping[3]["vendorOtherType"] == "NSP"
    assert mapping[3]["value"] == "796"
    assert mapping[3]["primary"] is True


def test_snyk_identifiers_to_threadfix_mapping_with_both_alternative_and_nsp():
    snyk_identifiers = {
        "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
        "CWE": ["CWE-400"],
        "NSP": [796],
        "ALTERNATIVE": ["SNYK-JS-BRACES-10900"],
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]["mappingType"] == "CVE"
    assert mapping[0]["value"] == "CVE-2019-11358"
    assert mapping[0]["primary"] is True

    assert mapping[1]["mappingType"] == "CVE"
    assert mapping[1]["value"] == "CVE-2019-5428"
    assert mapping[1]["primary"] is False

    assert mapping[2]["mappingType"] == "CWE"
    assert mapping[2]["value"] == "400"
    assert mapping[2]["primary"] is True

    assert mapping[3]["mappingType"] == "TOOL_VENDOR"
    assert mapping[3]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[3]["value"] == "SNYK-JS-BRACES-10900"
    assert mapping[3]["primary"] is True

    assert mapping[4]["mappingType"] == "TOOL_VENDOR"
    assert mapping[4]["vendorOtherType"] == "NSP"
    assert mapping[4]["value"] == "796"
    assert mapping[4]["primary"] is False  # the "ALTERNATIVE should get marked primary


def test_snyk_identifiers_to_threadfix_mapping_with_multiple_alternative_and_nsp():
    snyk_identifiers = {
        "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
        "CWE": ["CWE-400"],
        "NSP": [796, 123],
        "ALTERNATIVE": ["SNYK-JS-BRACES-10900", "abc123"],
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]["mappingType"] == "CVE"
    assert mapping[0]["value"] == "CVE-2019-11358"
    assert mapping[0]["primary"] is True

    assert mapping[1]["mappingType"] == "CVE"
    assert mapping[1]["value"] == "CVE-2019-5428"
    assert mapping[1]["primary"] is False

    assert mapping[2]["mappingType"] == "CWE"
    assert mapping[2]["value"] == "400"
    assert mapping[2]["primary"] is True

    assert mapping[3]["mappingType"] == "TOOL_VENDOR"
    assert mapping[3]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[3]["value"] == "SNYK-JS-BRACES-10900"
    assert mapping[3]["primary"] is True

    assert mapping[4]["mappingType"] == "TOOL_VENDOR"
    assert mapping[4]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[4]["value"] == "abc123"
    assert mapping[4]["primary"] is False

    assert mapping[5]["mappingType"] == "TOOL_VENDOR"
    assert mapping[5]["vendorOtherType"] == "NSP"
    assert mapping[5]["value"] == "796"
    assert mapping[5]["primary"] is False  # the "ALTERNATIVE should get marked primary

    assert mapping[6]["mappingType"] == "TOOL_VENDOR"
    assert mapping[6]["vendorOtherType"] == "NSP"
    assert mapping[6]["value"] == "123"
    assert mapping[6]["primary"] is False  # the "ALTERNATIVE should get marked primary


def test_snyk_identifiers_to_threadfix_mapping_with_multiple_alternative_and_nsp_and_unknown_identifiers():
    snyk_identifiers = {
        "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
        "CWE": ["CWE-400"],
        "NSP": ["796", "123"],
        "ALTERNATIVE": ["SNYK-JS-BRACES-10900", "abc123"],
        "SOME_OTHER_IDENTIFIER_TYPE": ["some-text-val", 123456],
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]["mappingType"] == "CVE"
    assert mapping[0]["value"] == "CVE-2019-11358"
    assert mapping[0]["primary"] is True

    assert mapping[1]["mappingType"] == "CVE"
    assert mapping[1]["value"] == "CVE-2019-5428"
    assert mapping[1]["primary"] is False

    assert mapping[2]["mappingType"] == "CWE"
    assert mapping[2]["value"] == "400"
    assert mapping[2]["primary"] is True

    assert mapping[3]["mappingType"] == "TOOL_VENDOR"
    assert mapping[3]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[3]["value"] == "SNYK-JS-BRACES-10900"
    assert mapping[3]["primary"] is True

    assert mapping[4]["mappingType"] == "TOOL_VENDOR"
    assert mapping[4]["vendorOtherType"] == "ALTERNATIVE"
    assert mapping[4]["value"] == "abc123"
    assert mapping[4]["primary"] is False

    assert mapping[5]["mappingType"] == "TOOL_VENDOR"
    assert mapping[5]["vendorOtherType"] == "NSP"
    assert mapping[5]["value"] == "796"
    assert mapping[5]["primary"] is False  # the "ALTERNATIVE should get marked primary

    assert mapping[6]["mappingType"] == "TOOL_VENDOR"
    assert mapping[6]["vendorOtherType"] == "NSP"
    assert mapping[6]["value"] == "123"
    assert mapping[6]["primary"] is False  # the "ALTERNATIVE should get marked primary

    assert mapping[6]["mappingType"] == "TOOL_VENDOR"
    assert mapping[6]["vendorOtherType"] == "NSP"
    assert mapping[6]["value"] == "123"
    assert mapping[6]["primary"] is False  # the "ALTERNATIVE should get marked primary

    assert mapping[7]["mappingType"] == "TOOL_VENDOR"
    assert mapping[7]["vendorOtherType"] == "SOME_OTHER_IDENTIFIER_TYPE"
    assert mapping[7]["value"] == "some-text-val"
    assert mapping[7]["primary"] is False  # the "ALTERNATIVE should get marked primary

    assert mapping[8]["mappingType"] == "TOOL_VENDOR"
    assert mapping[8]["vendorOtherType"] == "SOME_OTHER_IDENTIFIER_TYPE"
    assert mapping[8]["value"] == "123456"
    assert mapping[8]["primary"] is False  # the "ALTERNATIVE should get marked primary


def test_param_parsing_project_no_org_bad():
    cl_args = ["--project-ids", "id0"]
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit


def test_param_parsing_project_ids_list_ok():
    cl_args = ["--org-id", "123org", "--project-ids", "id0"]
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == "id0"

    cl_args = ["--org-id", "123org", "--project-ids", "id0,id1,id2"]
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == "id0"
    assert args.project_ids[1] == "id1"
    assert args.project_ids[2] == "id2"


def test_param_parsing_project_ids_empty_list_bad():
    cl_args = ["--org-id", "123org", "--project-ids", ""]
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit

    cl_args = ["--org-id", "123org", "--project-ids"]
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit


def test_parse_snyk_project_name_works_when_branch_names_used():
    project_name = "snyk-org/goof(master):package.json"
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert project_name_metadata["repo"] == "snyk-org/goof"
    assert project_name_metadata["branch"] == "master"
    assert project_name_metadata["targetFile"] == "package.json"


def test_parse_snyk_project_name_works_when_branch_names_not_used():
    project_name = "snyk-org/goof:package.json"
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert project_name_metadata["repo"] == "snyk-org/goof"
    assert project_name_metadata["targetFile"] == "package.json"
    assert "branch" not in project_name_metadata


def test_parse_snyk_project_name_works_with_custom_project_name():
    project_name = "custom-project-name"
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert "repo" not in project_name_metadata
    assert "targetFile" not in project_name_metadata
    assert "branch" not in project_name_metadata


def test_handle_invalid_input_parameter_values_nicely(capsys):
    cl_args = ["--org-id", "123org", "--project-ids", "123"]

    with patch("snyk_threadfix.main.get_token", return_value="some-token"):
        with patch("snyk_threadfix.main.validate_token", return_value=True):
            with patch(
                "snyk_threadfix.main.create_threadfix_findings_data", return_value=False
            ) as create_threadfix_findings_data_mock:
                create_threadfix_findings_data_mock.side_effect = (
                    snyk.errors.SnykNotFoundError()
                )

                main.main(cl_args)
                captured_out = capsys.readouterr()

                assert (
                    "Error resolving org / project(s) in Snyk. This is probably your `--org-id` or `--project-ids` parameters contains invalid value(s)."
                    in captured_out.err
                )
                assert create_threadfix_findings_data_mock.call_count == 1

            with patch(
                "snyk_threadfix.main.create_threadfix_findings_data", return_value=False
            ) as create_threadfix_findings_data_mock:
                create_threadfix_findings_data_mock.side_effect = (
                    snyk.errors.SnykOrganizationNotFoundError()
                )

                main.main(cl_args)
                captured_out = capsys.readouterr()

                assert (
                    "Error resolving org in Snyk. This is probably because your `--org-id` parameter value is invalid."
                    in captured_out.err
                )
                assert create_threadfix_findings_data_mock.call_count == 1


class DottedDictionary(dict):
    """Helper class for to be able to easily define a Python dictionary but then be able to use
    dot syntax on it to make it quack like the duck you are try to quack like"""

    __getattr__ = dict.get


def test_create_finding_data_regular_project_from_git_repo():
    org_id = 123
    snyk_project = {
        "name": "some-github-org/some-repo-name(master):package.json",
        "id": "65262451-7925-4f27-9675-f94d7d694e0f",
        "created": "2019-07-22T19:19:31.234Z",
        "origin": "github",
        "type": "npm",
        "readOnly": False,
        "testFrequency": "daily",
        "totalDependencies": 473,
        "issueCountsBySeverity": {"low": 6, "high": 14, "medium": 19},
        "imageTag": "0.0.3",
        "lastTestedDate": "2019-10-13T03:55:21.434Z",
        "browseUrl": "https://app.snyk.io/org/snyk-threadfix-test-org/project/65262451-7925-4f27-9675-f94d7d694e0f",
    }

    project_map = DottedDictionary(snyk_project)

    snyk_project_metadata = main.parse_snyk_project_name(snyk_project["name"])
    assert snyk_project_metadata["repo"] == "some-github-org/some-repo-name"
    assert snyk_project_metadata["branch"] == "master"
    assert snyk_project_metadata["targetFile"] == "package.json"

    snyk_vulnerability = {
        "id": "SNYK-JS-JQUERY-174006",
        "url": "https://snyk.io/vuln/SNYK-JS-JQUERY-174006",
        "title": "Prototype Pollution",
        "type": "vuln",
        "description": "",
        "fromPackages": ["jquery@2.2.4"],
        "package": "jquery",
        "version": "2.2.4",
        "severity": "medium",
        "language": "js",
        "packageManager": "npm",
        "semver": {"vulnerable": ["<3.4.0"]},
        "publicationTime": "2019-03-27T08:40:08Z",
        "disclosureTime": "2019-03-26T08:40:15Z",
        "isUpgradable": True,
        "isPatchable": False,
        "isPinnable": False,
        "identifiers": {
            "CVE": ["CVE-2019-11358", "CVE-2019-5428"],
            "CWE": ["CWE-400"],
            "NSP": [796],
        },
        "credit": ["Semmle Security Research Team"],
        "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cvssScore": 5.6,
        "patches": [],
        "upgradePath": ["jquery@3.4.0"],
    }

    vuln_map = DottedDictionary(snyk_vulnerability)

    tf_finding = main.create_finding_data(
        org_id, project_map, snyk_project_metadata, vuln_map
    )

    assert tf_finding["nativeId"] == main.generate_native_id(
        org_id,
        snyk_project["id"],
        snyk_vulnerability["id"],
        snyk_vulnerability["fromPackages"],
    )
    assert tf_finding["severity"] == snyk_vulnerability["severity"]
    assert tf_finding["nativeSeverity"] == "medium"
    assert tf_finding["summary"] == snyk_vulnerability["title"]
    assert (
        tf_finding["description"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert (
        tf_finding["scannerDetail"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert tf_finding["scannerRecommendation"] == snyk_vulnerability["url"]

    assert tf_finding["dependencyDetails"]["library"] == snyk_vulnerability["package"]
    assert (
        tf_finding["dependencyDetails"]["description"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert tf_finding["dependencyDetails"]["reference"] == snyk_vulnerability["id"]
    assert tf_finding["dependencyDetails"]["referenceLink"] == "%s#issue-%s" % (
        snyk_project["browseUrl"],
        snyk_vulnerability["id"],
    )

    assert tf_finding["dependencyDetails"]["version"] == snyk_vulnerability["version"]
    assert tf_finding["dependencyDetails"]["issueType"] == "VULNERABILITY"

    assert tf_finding["metadata"]["language"] == snyk_vulnerability["language"]
    assert (
        tf_finding["metadata"]["packageManager"] == snyk_vulnerability["packageManager"]
    )
    assert tf_finding["metadata"]["CVSSv3"] == snyk_vulnerability["CVSSv3"]
    assert tf_finding["metadata"]["cvssScore"] == snyk_vulnerability["cvssScore"]
    assert tf_finding["metadata"]["snyk_source"] == snyk_project["origin"]
    assert tf_finding["metadata"]["snyk_project_id"] == snyk_project["id"]
    assert tf_finding["metadata"]["snyk_project_name"] == snyk_project["name"]
    assert tf_finding["metadata"]["snyk_project_url"] == snyk_project["browseUrl"]
    assert tf_finding["metadata"]["snyk_organization"] == org_id

    assert tf_finding["metadata"]["snyk_repo"] == snyk_project_metadata["repo"]
    assert (
        tf_finding["metadata"]["snyk_target_file"]
        == snyk_project_metadata["targetFile"]
    )
    assert tf_finding["metadata"]["snyk_branch"] == "master"

    assert tf_finding["mappings"][0]["mappingType"] == "CVE"
    assert tf_finding["mappings"][0]["value"] == "CVE-2019-11358"
    assert tf_finding["mappings"][0]["primary"] is True

    assert tf_finding["mappings"][1]["mappingType"] == "CVE"
    assert tf_finding["mappings"][1]["value"] == "CVE-2019-5428"
    assert tf_finding["mappings"][1]["primary"] is False

    assert tf_finding["mappings"][2]["mappingType"] == "CWE"
    assert tf_finding["mappings"][2]["value"] == "400"
    assert tf_finding["mappings"][2]["primary"] is True

    assert tf_finding["mappings"][3]["mappingType"] == "TOOL_VENDOR"
    assert tf_finding["mappings"][3]["value"] == "796"
    assert tf_finding["mappings"][3]["vendorOtherType"] == "NSP"
    assert tf_finding["mappings"][3]["primary"] is True


def test_create_finding_data_regular_project_from_cli_project_with_custom_name():
    org_id = 123
    snyk_project = {
        "name": "another-jar-test",
        "id": "8dd49293-4ecc-4841-bd89-c871cdf1fb60",
        "created": "2019-10-04T18:25:23.119Z",
        "origin": "cli",
        "type": "maven",
        "readOnly": False,
        "testFrequency": "daily",
        "totalDependencies": 61,
        "issueCountsBySeverity": {"low": 0, "high": 24, "medium": 3},
        "imageTag": "1.0-SNAPSHOT",
        "lastTestedDate": "2019-10-15T04:57:55.049Z",
        "browseUrl": "https://app.snyk.io/org/snyk-threadfix-test-org/project/8dd49293-4ecc-4841-bd89-c871cdf1fb60",
    }

    project_map = DottedDictionary(snyk_project)

    snyk_project_metadata = main.parse_snyk_project_name(snyk_project["name"])

    snyk_vulnerability = {
        "id": "SNYK-JAVA-ORGSLF4J-32138",
        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGSLF4J-32138",
        "title": "Deserialization of Untrusted Data",
        "type": "vuln",
        "description": "",
        "fromPackages": [
            "org.openapitools:openapi-generator@3.2.3",
            "org.slf4j:slf4j-ext@1.7.12",
        ],
        "package": "org.slf4j:slf4j-ext",
        "version": "1.7.12",
        "severity": "high",
        "language": "java",
        "packageManager": "maven",
        "semver": {"vulnerable": ["[,1.7.26)", "[1.8.0-alpha0,1.8.0-beta2)"]},
        "publicationTime": "2018-03-21T09:26:19Z",
        "disclosureTime": "2018-03-20T17:07:02Z",
        "isUpgradable": False,
        "isPatchable": False,
        "isPinnable": False,
        "identifiers": {"CVE": ["CVE-2018-8088"], "CWE": ["CWE-502"]},
        "credit": ["Unknown"],
        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvssScore": 9.8,
        "patches": [],
        "upgradePath": [],
    }

    vuln_map = DottedDictionary(snyk_vulnerability)

    tf_finding = main.create_finding_data(
        org_id, project_map, snyk_project_metadata, vuln_map
    )

    assert tf_finding["nativeId"] == main.generate_native_id(
        org_id,
        snyk_project["id"],
        snyk_vulnerability["id"],
        snyk_vulnerability["fromPackages"],
    )
    assert tf_finding["severity"] == snyk_vulnerability["severity"]
    assert tf_finding["nativeSeverity"] == "high"
    assert tf_finding["summary"] == snyk_vulnerability["title"]
    assert (
        tf_finding["description"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert (
        tf_finding["scannerDetail"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert tf_finding["scannerRecommendation"] == snyk_vulnerability["url"]

    assert tf_finding["dependencyDetails"]["library"] == snyk_vulnerability["package"]
    assert (
        tf_finding["dependencyDetails"]["description"]
        == "You can find the description here: %s" % snyk_vulnerability["url"]
    )
    assert tf_finding["dependencyDetails"]["reference"] == snyk_vulnerability["id"]
    assert tf_finding["dependencyDetails"]["referenceLink"] == "%s#issue-%s" % (
        snyk_project["browseUrl"],
        snyk_vulnerability["id"],
    )

    assert tf_finding["dependencyDetails"]["version"] == snyk_vulnerability["version"]
    assert tf_finding["dependencyDetails"]["issueType"] == "VULNERABILITY"

    assert tf_finding["metadata"]["language"] == snyk_vulnerability["language"]
    assert (
        tf_finding["metadata"]["packageManager"] == snyk_vulnerability["packageManager"]
    )
    assert tf_finding["metadata"]["CVSSv3"] == snyk_vulnerability["CVSSv3"]
    assert tf_finding["metadata"]["cvssScore"] == snyk_vulnerability["cvssScore"]
    assert tf_finding["metadata"]["snyk_source"] == snyk_project["origin"]
    assert tf_finding["metadata"]["snyk_project_id"] == snyk_project["id"]
    assert tf_finding["metadata"]["snyk_project_name"] == snyk_project["name"]
    assert tf_finding["metadata"]["snyk_project_url"] == snyk_project["browseUrl"]
    assert tf_finding["metadata"]["snyk_organization"] == org_id

    assert tf_finding["mappings"][0]["mappingType"] == "CVE"
    assert tf_finding["mappings"][0]["value"] == "CVE-2018-8088"
    assert tf_finding["mappings"][0]["primary"] is True

    assert tf_finding["mappings"][1]["mappingType"] == "CWE"
    assert tf_finding["mappings"][1]["value"] == "502"
    assert tf_finding["mappings"][1]["primary"] is True


def test_module_version_matches_pyproject_version():
    """Verify that the __version__ in the module is being correctly pulled from the pyproject.toml config"""
    version_from_package_init = __version__

    # this is so that the test finds the pyproject.toml file when run from the command line or from within Pycharm
    this_directory = os.path.dirname(os.path.realpath(__file__))
    pyproject_toml_path = os.path.join(this_directory, "..", "pyproject.toml")

    with open(pyproject_toml_path) as pyproject_file:
        pyproject_contents = pyproject_file.read()

    pyproject_meta_data = tomlkit.parse(pyproject_contents)["tool"]["poetry"]
    version_from_pyproject = pyproject_meta_data["version"]

    assert version_from_package_init == version_from_pyproject
