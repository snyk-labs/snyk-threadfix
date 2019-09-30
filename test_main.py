import main
import pytest


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
    cl_args = ['--projectIds', 'id0']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit


def test_param_parsing_project_ids_list_ok():
    cl_args = ['--orgId', '123org', '--projectIds', 'id0']
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == 'id0'

    cl_args = ['--orgId', '123org', '--projectIds', 'id0,id1,id2']
    args = main.parse_command_line_args(cl_args)
    assert args.project_ids[0] == 'id0'
    assert args.project_ids[1] == 'id1'
    assert args.project_ids[2] == 'id2'


def test_param_parsing_project_ids_empty_list_bad():
    cl_args = ['--orgId', '123org', '--projectIds', '']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit

    cl_args = ['--orgId', '123org', '--projectIds']
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        args = main.parse_command_line_args(cl_args)
    assert pytest_wrapped_exception.type == SystemExit
