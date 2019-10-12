from snyk_threadfix import main
import pytest
import snyk
from mock import patch


def test_snyk_identifiers_to_threadfix_mapping():
    snyk_identifiers = {
        'CVE': [
            'CVE-2019-11358',
            'CVE-2019-5428'
        ],
        'CWE': [
            'CWE-185',
            'CWE-400'
        ],
        'ALTERNATIVE': [
            "SNYK-JS-BRACES-10900"
        ]
    }

    mapping = main.snyk_identifiers_to_threadfix_mappings(snyk_identifiers)

    assert mapping[0]['mappingType'] == 'CVE'
    assert mapping[0]['value'] == 'CVE-2019-11358'
    assert mapping[0]['primary'] is False

    assert mapping[1]['mappingType'] == 'CVE'
    assert mapping[1]['value'] == 'CVE-2019-5428'
    assert mapping[1]['primary'] is False

    assert mapping[2]['mappingType'] == 'CWE'
    assert mapping[2]['value'] == '185'
    assert mapping[2]['primary'] is True

    assert mapping[3]['mappingType'] == 'CWE'
    assert mapping[3]['value'] == '400'
    assert mapping[3]['primary'] is False

    assert mapping[4]['mappingType'] == 'ALTERNATIVE'
    assert mapping[4]['value'] == 'SNYK-JS-BRACES-10900'
    assert mapping[4]['primary'] is False


def test_param_parsing_project_no_org_bad():
    cl_args = ['--project-ids', 'id0']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit


def test_param_parsing_project_ids_list_ok():
    cl_args = ['--org-id', '123org', '--project-ids', 'id0']
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == 'id0'

    cl_args = ['--org-id', '123org', '--project-ids', 'id0,id1,id2']
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == 'id0'
    assert args.project_ids[1] == 'id1'
    assert args.project_ids[2] == 'id2'


def test_param_parsing_project_ids_empty_list_bad():
    cl_args = ['--org-id', '123org', '--project-ids', '']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit

    cl_args = ['--org-id', '123org', '--project-ids']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit


def test_parse_snyk_project_name_works_when_branch_names_used():
    project_name = 'snyk-org/goof(master):package.json'
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert project_name_metadata['repo'] == 'snyk-org/goof'
    assert project_name_metadata['branch'] == 'master'
    assert project_name_metadata['targetFile'] == 'package.json'


def test_parse_snyk_project_name_works_when_branch_names_not_used():
    project_name = 'snyk-org/goof:package.json'
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert project_name_metadata['repo'] == 'snyk-org/goof'
    assert project_name_metadata['targetFile'] == 'package.json'
    assert 'branch' not in project_name_metadata


def test_parse_snyk_project_name_works_with_custom_project_name():
    project_name = 'custom-project-name'
    project_name_metadata = main.parse_snyk_project_name(project_name)
    assert 'repo' not in project_name_metadata
    assert 'targetFile' not in project_name_metadata
    assert 'branch' not in project_name_metadata


def test_handle_invalid_input_parameter_values_nicely(capsys):
    cl_args = [
        '--org-id', '123org',
        '--project-ids', '123'
    ]

    with patch('snyk_threadfix.main.get_token', return_value='some-token'):
        with patch('snyk_threadfix.main.validate_token', return_value=True):
            with patch('snyk_threadfix.main.create_threadfix_findings_data', return_value=False) as create_threadfix_findings_data_mock:
                create_threadfix_findings_data_mock.side_effect = snyk.errors.SnykNotFoundError()

                main.main(cl_args)
                captured_out = capsys.readouterr()

                assert 'Error resolving org / project(s) in Snyk. This is probably your `--org-id` or `--project-ids` parameters contains invalid value(s).' in captured_out.err
                assert create_threadfix_findings_data_mock.call_count == 1

            with patch('snyk_threadfix.main.create_threadfix_findings_data', return_value=False) as create_threadfix_findings_data_mock:
                create_threadfix_findings_data_mock.side_effect = snyk.errors.SnykOrganizationNotFoundError()

                main.main(cl_args)
                captured_out = capsys.readouterr()

                assert 'Error resolving org in Snyk. This is probably because your `--org-id` parameter value is invalid.' in captured_out.err
                assert create_threadfix_findings_data_mock.call_count == 1
