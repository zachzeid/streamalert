"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import base64
from collections import defaultdict
import json
import os
import re
import time
import zlib

from mock import patch, MagicMock

from streamalert.alert_processor import main as alert_processor
from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import OutputDispatcher
from streamalert.classifier import classifier
from streamalert.classifier.parsers import ParserBase
from streamalert.rules_engine import rules_engine
from streamalert.shared import rule
from streamalert.shared.logger import get_logger
from streamalert.shared.stats import RuleStatisticTracker
from streamalert.shared.lookup_tables.table import LookupTable
from streamalert_cli.helpers import check_credentials
from streamalert_cli.test import DEFAULT_TEST_FILES_DIRECTORY
from streamalert_cli.test.format import format_green, format_red, format_underline, format_yellow
from streamalert_cli.test.integration_test import IntegrationTestFile
from streamalert_cli.test.mocks import mock_lookup_table_results, mock_threat_intel_query_results
from streamalert_cli.test.results import TestEventFile, TestResult
from streamalert_cli.utils import CLICommand, generate_subparser, UniqueSetAction

LOGGER = get_logger(__name__)


class TestCommand(CLICommand):
    description = 'Perform various integration/functional tests'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the test subparser: manage.py test"""
        test_subparsers = subparser.add_subparsers(dest="test subcommand", required=True)

        cls._setup_test_classifier_subparser(test_subparsers)
        cls._setup_test_rules_subparser(test_subparsers)
        cls._setup_test_live_subparser(test_subparsers)

    @classmethod
    def _setup_test_classifier_subparser(cls, subparsers):
        """Add the test validation subparser: manage.py test classifier [options]"""
        test_validate_parser = generate_subparser(
            subparsers,
            'classifier',
            description='Validate defined log schemas using integration test files',
            subcommand=True
        )

        cls._add_default_test_args(test_validate_parser)

    @classmethod
    def _setup_test_rules_subparser(cls, subparsers):
        """Add the test rules subparser: manage.py test rules [options]"""
        test_rules_parser = generate_subparser(
            subparsers,
            'rules',
            description='Test rules using integration test files',
            subcommand=True
        )

        # Flag to run additional stats during testing
        test_rules_parser.add_argument(
            '-s',
            '--stats',
            action='store_true',
            help='Enable outputing of statistical information on rules that run'
        )

        # Validate the provided repitition value
        def _validate_repitition(val):
            """Make sure the input is between 1 and 1000"""
            err = ('Invalid repitition value [{}]. Must be an integer between 1 '
                   'and 1000').format(val)
            try:
                count = int(val)
            except TypeError:
                raise test_rules_parser.error(err)

            if not 1 <= count <= 1000:
                raise test_rules_parser.error(err)

            return count

        # flag to run these tests a given number of times
        test_rules_parser.add_argument(
            '-n',
            '--repeat',
            default=1,
            type=_validate_repitition,
            help='Number of times to repeat the tests, to be used as a form performance testing'
        )

        cls._add_default_test_args(test_rules_parser)

    @classmethod
    def _setup_test_live_subparser(cls, subparsers):
        """Add the test live subparser: manage.py test live [options]"""
        test_live_parser = generate_subparser(
            subparsers,
            'live',
            description=(
                'Run end-to-end tests that will attempt to send alerts to each rule\'s outputs'
            ),
            subcommand=True
        )

        cls._add_default_test_args(test_live_parser)

    @staticmethod
    def _add_default_test_args(test_parser):
        """Add the default arguments to the test parsers"""
        test_filter_group = test_parser.add_mutually_exclusive_group(required=False)

        # add the optional ability to test against a rule/set of rules
        test_filter_group.add_argument(
            '-f',
            '--test-files',
            dest='files',
            metavar='FILENAMES',
            nargs='+',
            help='One or more file to test, separated by spaces',
            action=UniqueSetAction,
            default=set()
        )

        # add the optional ability to test against a rule/set of rules
        test_filter_group.add_argument(
            '-r',
            '--test-rules',
            dest='rules',
            nargs='+',
            help='One or more rule to test, separated by spaces',
            action=UniqueSetAction,
            default=set()
        )

        # add the optional ability to change the test files directory
        test_parser.add_argument(
            '-d',
            '--files-dir',
            help='Path to directory containing test files',
            default=DEFAULT_TEST_FILES_DIRECTORY
        )

        # Add the optional ability to log verbosely or use quite logging for tests
        verbose_group = test_parser.add_mutually_exclusive_group(required=False)

        verbose_group.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help='Output additional information during testing'
        )

        verbose_group.add_argument(
            '-q',
            '--quiet',
            action='store_true',
            help='Suppress output for passing tests, only logging if there is a failure'
        )

    @classmethod
    def handler(cls, options, config):
        """Handler for starting the test framework

        Args:
            options (argparse.Namespace): Parsed arguments
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        result = True
        opts = vars(options)
        repeat = opts.get('repeat', 1)
        for i in range(repeat):
            if repeat != 1:
                print('\nRepetition #', i+1)
            result = result and TestRunner(options, config).run()

        if opts.get('stats'):
            print(RuleStatisticTracker.statistics_info())
        return result


class TestRunner:
    """TestRunner to handle running various tests"""

    class Types:
        """Simple types enum for test types"""
        CLASSIFY = 'classifier'
        RULES = 'rules'
        LIVE = 'live'

    def __init__(self, options, config):
        self._config = config
        self._options = options
        self._type = options.subcommand
        self._files = options.files
        self._rules = options.rules
        self._files_dir = os.path.join(options.files_dir, '')  # ensure theres a trailing slash
        self._verbose = options.verbose
        self._quiet = options.quiet
        self._s3_mocker = patch('streamalert.classifier.payload.s3.boto3.resource').start()
        self._errors = defaultdict(list)  # cache errors to be logged at the endpoint
        self._tested_rules = set()
        self._threat_intel_mock = mock_threat_intel_query_results()
        self._lookup_tables_mock = mock_lookup_table_results()
        self._passed = 0
        self._failed = 0
        prefix = self._config['global']['account']['prefix']
        env = {
            'CLUSTER': 'prod',
            'STREAMALERT_PREFIX': prefix,
            'AWS_ACCOUNT_ID': self._config['global']['account']['aws_account_id'],
            'ALERTS_TABLE': '{}_streamalert_alerts'.format(prefix),
        }

        if 'stats' in options and options.stats:
            env['STREAMALERT_TRACK_RULE_STATS'] = '1'

        patch.dict(
            os.environ,
            env
        ).start()

    def _run_rules_engine(self, record):
        """Create a fresh rules engine and process the record, returning the result"""
        with patch.object(rules_engine.ThreatIntel, '_query') as ti_mock, \
             patch.object(rules_engine, 'AlertForwarder'), \
             patch.object(rules_engine, 'RuleTable') as rule_table, \
             patch('rules.helpers.base.random_bool', return_value=True):

            # Emptying out the rule table will force all rules to be unstaged, which causes
            # non-required outputs to get properly populated on the Alerts that are generated
            # when running the Rules Engine.
            rule_table.return_value = False
            ti_mock.side_effect = self._threat_intel_mock

            _rules_engine = rules_engine.RulesEngine()

            self._install_lookup_tables_mocks(_rules_engine)

            return _rules_engine.run(records=record)

    def _install_lookup_tables_mocks(self, rules_engine_instance):
        """
        Extremely gnarly, extremely questionable manner to install mocking data into our tables.
        The reason this exists at all is to support the secret features of table scanning S3-backed
        tables, which isn't a "normally" available feature but is required for some pre-existing
        StreamAlert users.
        """
        from streamalert.shared.lookup_tables.drivers import EphemeralDriver

        dummy_configuration = {}
        mock_data = self._lookup_tables_mock

        # pylint: disable=protected-access
        for table_name in rules_engine_instance._lookup_tables._tables.keys():
            driver = EphemeralDriver(dummy_configuration)
            driver._cache = mock_data.get(table_name, {})
            ephemeral_table = LookupTable(table_name, driver, dummy_configuration)

            rules_engine_instance._lookup_tables._tables[table_name] = ephemeral_table

    @staticmethod
    def _run_alerting(record):
        """Create a fresh alerts processor and send the alert(s), returning the result"""
        with patch.object(alert_processor, 'AlertTable'):
            alert_proc = alert_processor.AlertProcessor()

            return alert_proc.run(event=record.dynamo_record())

    def _check_prereqs(self):
        if self._type == self.Types.LIVE:
            return check_credentials()

        return True

    def _finalize(self):
        summary = [
            format_underline('\nSummary:\n'),
            'Total Tests: {}'.format(self._passed + self._failed),
            format_green('Pass: {}'.format(self._passed)) if self._passed else 'Pass: 0',
            format_red('Fail: {}\n'.format(self._failed)) if self._failed else 'Fail: 0\n',
        ]

        print('\n'.join(summary))

        for path in sorted(self._errors):
            for error in self._errors[path]:
                message = '({}) {}'.format(path, error) if path != 'error' else error
                LOGGER.error(message)

        # If rule are being tested and no filtering is being performed, log any untested rules
        if self._testing_rules and not self._is_filtered:
            all_rules = set(rule.Rule.rule_names()) - rule.Rule.disabled_rules()
            untested_rules = sorted(all_rules.difference(self._tested_rules))
            if not untested_rules:
                return
            print(format_yellow('No test events configured for the following rules:'))
            for rule_name in untested_rules:
                print(format_yellow(rule_name))

    @property
    def _is_filtered(self):
        return bool(self._files or self._rules)

    @property
    def _testing_rules(self):
        return self._type in {self.Types.RULES, self.Types.LIVE}

    def run(self):
        """Run the tests"""
        if not self._check_prereqs():
            return

        print('\nRunning tests for files found in: {}'.format(self._files_dir))


        for file in self._get_test_files():
            test_file = IntegrationTestFile(
                file.replace(self._files_dir, ''),
                file,
                self._config
            )

            # FIXME (ryxias) refactor this
            test_event = TestEventFile(file.replace(self._files_dir, ''))

            for test in test_file.tests:
                if not test.valid:
                    continue

                if not test.contains_rules(self._rules):
                    continue

                for cluster_name, cluster_value in self._config['clusters'].items():
                    for service in cluster_value['data_sources'].values():
                        if test.resource in service:
                            os.environ['CLUSTER'] = cluster_name
                            break

                classifier_result = test.run_classification()

                test_result = TestResult(
                    test.testfile_index,
                    test.config,
                    classifier_result[0] if classifier_result else False,
                    with_rules=self._testing_rules,
                    verbose=self._verbose
                )

                test_event.add_result(test_result)

                self._tested_rules.update(test_result.expected_rules)

                if not test_result:
                    continue

                if test.is_validate_schema_only:
                    continue  # Do not run rules on events that are only for validation

                if self._type in {self.Types.RULES, self.Types.LIVE}:
                    alerts = self._run_rules_engine(classifier_result[0].sqs_messages)
                    test_result.alerts = alerts

                    if not test.skip_publishers:
                        for alert in alerts:
                            publication_results = self._run_publishers(alert)
                            test_result.set_publication_results(publication_results)

                    if self._type == self.Types.LIVE:
                        for alert in alerts:
                            alert_result = self._run_alerting(alert)
                            test_result.add_live_test_result(alert.rule_name, alert_result)

            self._passed += test_event.passed
            self._failed += test_event.failed

            # It is possible for a test_event to have no results,
            # so only print it if it does and if quiet mode is no being used
            # Quite mode is overridden if not all of the events passed
            if test_event and not (self._quiet and test_event.all_passed):
                print(test_event)

        self._finalize()

        return self._failed == 0

    @staticmethod
    def _run_publishers(alert):
        """Runs publishers for all currently configured outputs on the given alert

        Args:
            - alert (Alert): The alert

        Returns:
            dict: A dict keyed by output:descriptor strings, mapped to nested dicts.
                  The nested dicts have 2 keys:
                  - publication (dict): The dict publication
                  - success (bool): True if the publishing finished, False if it errored.
        """
        configured_outputs = alert.outputs

        results = {}
        for configured_output in configured_outputs:
            [output_name, descriptor] = configured_output.split(':')

            try:
                output = MagicMock(spec=OutputDispatcher, __service__=output_name)
                results[configured_output] = {
                    'publication': compose_alert(alert, output, descriptor),
                    'success': True,
                }
            except (RuntimeError, TypeError, NameError) as err:
                results[configured_output] = {
                    'success': False,
                    'error': err,
                }
        return results

    def _get_test_files(self):
        """Helper to get rule files to be tested

        Yields:
            str: Path to test event file
        """
        files_filter = {
            os.path.splitext(name)[0] for name in self._files
        } if self._files else set()

        filtered = bool(files_filter)
        for root, _, test_event_files in os.walk(self._files_dir):
            for event_file in sorted(test_event_files):
                basename = os.path.splitext(event_file)[0]
                full_path = os.path.join(root, event_file)
                if not filtered or basename in files_filter:
                    yield full_path
                    if filtered:
                        files_filter.remove(basename)  # Remove this from the filter

        # Log any errors for filtered items that do not exist
        for basename in files_filter:
            self._append_error('No test event file found with base name \'{}\''.format(basename))

    def _append_error(self, error, path=None, idx=None):
        key = 'error'
        if path:
            key = os.path.split(path)[1]
        key = key if not idx else '{}:{}'.format(key, idx)
        self._errors[key].append(error)


