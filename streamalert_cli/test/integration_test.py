import base64
import json
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
from streamalert.shared.lookup_tables.table import LookupTable
from streamalert_cli.test.mocks import mock_threat_intel_query_results, mock_lookup_table_results

LOGGER = get_logger(__name__)


class IntegrationTestFile:
    """Encapsulation of a single .json test file.

    A single test file can contain multiple individual tests. Test files should be formatted as:

        [
            {
                "data": {},
                "description": "...",
                "...": "..."
            },
            {
              ...
            }
        ]
    """

    def __init__(self, test_name, path, config):
        """
        Args:
            test_name (str): Name of this test
            path (str): Relative path to file on disk
            config (dict): StreamAlert configuration
        """
        self._test_name = test_name
        self._config_filepath = path
        self._streamalert_config = config

        self._tests = []

    @property
    def test_name(self):
        return self._test_name

    @property
    def streamalert_config(self):
        return self._streamalert_config

    @property
    def tests(self):
        """Helper to json load the contents of a file with some error handling

        Yields:
            list[IntegrationTest]: List of all integation tests associated with this
        """
        with open(self._config_filepath, 'r') as test_event_file:
            try:
                data = json.load(test_event_file)
            except (ValueError, TypeError):
                # FIXME ???
                LOGGER.error('Test event file is not valid JSON', path=self._config_filepath)
                return

            if not isinstance(data, list):
                # FIXME ???
                LOGGER.error('Test event file is improperly formatted', path=self._config_filepath)
                return

            for idx, event in enumerate(data):

                test = IntegrationTest(self, idx, event)

                if not test.valid:
                    LOGGER.error(test, path=self._config_filepath, idx=idx)
                    continue

                yield test


class IntegrationTest:

    def __init__(self, test_file, index, configuration):
        self._index = index
        self._test_file = test_file
        self._configuration = configuration
        self._valid = False
        self._error = None
        self._test_record = None

        self._s3_mocker = patch('streamalert.classifier.payload.s3.boto3.resource').start()
        self._threat_intel_mock = mock_threat_intel_query_results()
        self._lookup_tables_mock = mock_lookup_table_results()

        self._format_test_record()

    def __str__(self):
        return 'Test: {} #{}'.format(self._test_file.test_name, self._index)

    @property
    def valid(self):
        return self._valid

    @property
    def error(self):
        return self._error if not self.valid else None

    @property
    def testfile_index(self):
        return self._index

    @property
    def record(self):
        return self._test_record

    @property
    def config(self):
        return self._configuration

    @property
    def resource(self):
        return self.config['source']

    @property
    def is_validate_schema_only(self):
        return self.config.get('validate_schema_only', False)

    @property
    def skip_publishers(self):
        return self.config.get('skip_publishers', False)

    @property
    def expected_trigger_rules(self):
        return self.config.get('trigger_rules', [])

    def run_classification(self):
        """Create a fresh classifier and classify the record, returning the result"""
        with patch.object(classifier, 'SQSClient'), patch.object(classifier, 'FirehoseClient'):
            _classifier = classifier.Classifier()
            return _classifier.run(records=[self.record])

    def run_rules(self, records):
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

            return _rules_engine.run(records=records)

    @staticmethod
    def run_publishers(alert):
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

    @staticmethod
    def run_alerting(record):
        """Create a fresh alerts processor and send the alert(s), returning the result"""
        with patch.object(alert_processor, 'AlertTable'):
            alert_proc = alert_processor.AlertProcessor()

            return alert_proc.run(event=record.dynamo_record())

    def contains_rules(self, rules):
        if not rules:
            return True

        expected_rules = set(self.expected_trigger_rules) - rule.Rule.disabled_rules()
        return bool(expected_rules.intersection(rules))

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

    def _format_test_record(self):
        """Create a properly formatted Kinesis, S3, or SNS record.

        Supports a dictionary or string based data record.  Reads in
        event templates from the tests/integration/templates folder.

        Args:
            test_event (dict): Test event metadata dict with the following structure:
                data|override_record - string or dict of the raw data
                description - a string describing the test that is being performed
                trigger - bool of if the record should produce an alert
                source - which stream/s3 bucket originated the data
                service - which aws service originated the data
                compress (optional) - if the payload needs to be gzip compressed or not

        Returns:
            dict: in the format of the specific service
        """
        test_event = self._configuration

        valid, self._error = self._validate_test_event(test_event)
        if not valid:
            self._valid = False
            return

        self._apply_helpers(test_event)
        self._apply_defaults(test_event)

        data = test_event['data']
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, str):
            self._valid = False
            self._error = 'Invalid data type: {}'.format(type(data))
            return

        if test_event['service'] not in {'s3', 'kinesis', 'sns', 'streamalert_app'}:
            self._valid = False
            self._error = 'Unsupported service: {}'.format(test_event['service'])
            return

        # Get a formatted record for this particular service
        self._valid = True

        self._test_record = self._apply_service_template(
            test_event['service'],
            test_event['source'],
            data,
            test_event.get('compress', False)
        )

    @staticmethod
    def _validate_test_event(test_event):
        """Check if the test event contains the required keys

        Args:
            test_event (dict): The loaded test event from json

        Returns:
            tuple (bool, str):
                bool: True if the proper keys are present
                str: String describing error. None if no error.
        """
        required_keys = {'description', 'log', 'service', 'source'}

        test_event_keys = set(test_event)
        if not required_keys.issubset(test_event_keys):
            req_key_diff = required_keys.difference(test_event_keys)
            missing_keys = ', '.join('\'{}\''.format(key) for key in req_key_diff)
            return False, 'Missing required key(s) in test event: {}'.format(missing_keys)

        acceptable_data_keys = {'data', 'override_record'}
        if not test_event_keys & acceptable_data_keys:
            return False, 'Test event must contain either \'data\' or \'override_record\''

        optional_keys = {'compress', 'trigger_rules', 'validate_schema_only'}

        key_diff = test_event_keys.difference(required_keys | optional_keys | acceptable_data_keys)

        # Log a warning if there are extra keys declared in the test log
        if key_diff:
            extra_keys = ', '.join('\'{}\''.format(key) for key in key_diff)
            LOGGER.warning('Additional unnecessary keys in test event: %s', extra_keys)

        return True, None

    def _apply_defaults(self, test_event):
        """Apply default values to the given test event

        Args:
            test_event (dict): The loaded test event
        """
        if 'override_record' not in test_event:
            return

        event_log = self._test_file.streamalert_config['logs'].get(test_event['log'])

        configuration = event_log.get('configuration', {})
        schema = configuration.get('envelope_keys', event_log['schema'])

        # Add apply default values based on the declared schema
        default_test_event = {
            key: ParserBase.default_optional_values(value)
            for key, value in schema.items()
        }

        # Overwrite the fields included in the 'override_record' field,
        # and update the test event with a full 'data' key
        default_test_event.update(test_event['override_record'])
        test_event['data'] = default_test_event

    @staticmethod
    def _apply_helpers(test_record):
        """Detect and apply helper functions to test event data

        Helpers are declared in test fixtures via the following keyword:
        "<helpers:helper_name>"

        Supported helper functions:
            last_hour: return the current epoch time minus 60 seconds to pass the
                       last_hour rule helper.

        Args:
            test_record (dict): loaded fixture file JSON as a dict.
        """
        # declare all helper functions here, they should always return a string
        record_helpers = {
            'last_hour': lambda: str(int(time.time()) - 60)
        }
        helper_regex = re.compile(r'<helper:(?P<helper>\w+)>')

        def _find_and_apply_helpers(test_record):
            """Apply any helpers to the passed in test_record"""
            for key, value in test_record.items():
                if isinstance(value, str):
                    test_record[key] = re.sub(
                        helper_regex,
                        lambda match: record_helpers[match.group('helper')](),
                        value
                    )
                elif isinstance(value, dict):
                    _find_and_apply_helpers(test_record[key])

        _find_and_apply_helpers(test_record)

    def _apply_service_template(self, service, source, data, compress=False):
        """Provides a pre-configured template that reflects incoming payload from a service

        Args:
            service (str): The service for the payload template

        Returns:
            dict: Template of the payload for the given service
        """
        if service == 's3':
            # Assign the s3 mock for this data
            self._setup_s3_mock(data)
            return {
                'eventVersion': '2.0',
                'eventTime': '1970-01-01T00:00:00.000Z',
                'requestParameters': {
                    'sourceIPAddress': '127.0.0.1'
                },
                's3': {
                    'configurationId': ',,,',
                    'object': {
                        'eTag': '...',
                        'sequencer': '...',
                        'key': 'test_object_key',
                        'size': len(data)
                    },
                    'bucket': {
                        'arn': 'arn:aws:s3:::{}'.format(source),
                        'name': source,
                        'ownerIdentity': {
                            'principalId': 'EXAMPLE'
                        }
                    },
                    's3SchemaVersion': '1.0'
                },
                'responseElements': {
                    'x-amz-id-2': (
                        'EXAMPLE123/foo/bar'
                    ),
                    'x-amz-request-id': '...'
                },
                'awsRegion': 'us-east-1',
                'eventName': 'ObjectCreated:Put',
                'userIdentity': {
                    'principalId': 'EXAMPLE'
                },
                'eventSource': 'aws:s3'
            }

        if service == 'kinesis':
            if compress:
                data = zlib.compress(data)

            kinesis_data = base64.b64encode(data.encode())

            return {
                'eventID': '...',
                'eventVersion': '1.0',
                'kinesis': {
                    'approximateArrivalTimestamp': 1428537600,
                    'partitionKey': 'partitionKey-3',
                    'data': kinesis_data,
                    'kinesisSchemaVersion': '1.0',
                    'sequenceNumber': ',,,'
                },
                'invokeIdentityArn': 'arn:aws:iam::EXAMPLE',
                'eventName': 'aws:kinesis:record',
                'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/{}'.format(
                    source
                ),
                'eventSource': 'aws:kinesis',
                'awsRegion': 'us-east-1'
            }

        if service == 'sns':
            return {
                'EventVersion': '1.0',
                'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123456789012:{}'.format(source),
                'EventSource': 'aws:sns',
                'Sns': {
                    'SignatureVersion': '1',
                    'Timestamp': '1970-01-01T00:00:00.000Z',
                    'Signature': 'EXAMPLE',
                    'SigningCertUrl': 'EXAMPLE',
                    'MessageId': '95df01b4-ee98-5cb9-9903-4c221d41eb5e',
                    'Message': data,
                    'MessageAttributes': {
                        'Test': {
                            'Type': 'String',
                            'Value': 'TestString'
                        }
                    },
                    'Type': 'Notification',
                    'UnsubscribeUrl': '...',
                    'TopicArn': 'arn:aws:sns:us-east-1:123456789012:{}'.format(source),
                    'Subject': '...'
                }
            }

        if service == 'streamalert_app':
            return {'streamalert_app': source, 'logs': [data]}

    def _setup_s3_mock(self, data):
        self._s3_mocker.return_value.Bucket.return_value.download_fileobj = (
            lambda k, d: d.write(json.dumps(data).encode())
        )
