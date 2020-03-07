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
from collections import defaultdict
import os

from mock import patch

from streamalert.shared import rule
from streamalert.shared.logger import get_logger
from streamalert.shared.stats import RuleStatisticTracker
from streamalert_cli.helpers import check_credentials
from streamalert_cli.test import DEFAULT_TEST_FILES_DIRECTORY
from streamalert_cli.test.format import format_green, format_red, format_underline, format_yellow
from streamalert_cli.test.integration_test import IntegrationTestFile
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
                    alerts = test.run_rules(classifier_result[0].sqs_messages)
                    test_result.alerts = alerts

                    if not test.skip_publishers:
                        for alert in alerts:
                            publication_results = test.run_publishers(alert)
                            test_result.set_publication_results(publication_results)

                    if self._type == self.Types.LIVE:
                        for alert in alerts:
                            alert_result = test.run_alerting(alert)
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
