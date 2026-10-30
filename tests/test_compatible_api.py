"""Configurable Chat Completions transport, credential separation and safe status."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from http.client import HTTPResponse
from unittest.mock import patch
from urllib.error import HTTPError

from model_client import ModelSettings, DeepSeekClient, ModelUnavailableError, ModelOutputError
from natural_language_agent import NaturalLanguageInterpreter
from local_app import LocalSafetyApp

BASE = {'LLM_PROVIDER':'openai_compatible', 'LLM_BASE_URL':'https://gateway.example/custom/v1',
        'LLM_MODEL':'operator-model', 'LLM_API_KEY':'compatible-unit-secret',
        'DEEPSEEK_API_KEY':'must-not-use-deepseek-secret'}
ANALYSIS = '{"actionable":true,"intent":"查看磁盘","tool":"check_disk","arguments":{},"risk":"low","reason":"只读"}'


def settings(**updates):
    with tempfile.TemporaryDirectory() as directory:
        return ModelSettings.load(env_file=Path(directory)/'absent.env', environ={**BASE, **updates})


def response(content=ANALYSIS, finish='stop'):
    return io.BytesIO(json.dumps({'choices':[{'message':{'content':content}, 'finish_reason':finish}]}).encode())


class CompatibleAPITests(unittest.TestCase):
    def test_declared_http_length_must_be_fully_delivered_even_if_json_is_valid(self):
        payload = response().getvalue()
        class MemorySocket:
            def __init__(self, length): self.length=length
            def makefile(self, *args):
                return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(self.length).encode()+b'\r\n\r\n'+payload)
        for value in (settings(), ModelSettings.load(env_file=Path('absent.env'), environ={'DEEPSEEK_API_KEY':'synthetic-key'})):
            incoming=HTTPResponse(MemorySocket(len(payload)+100)); incoming.begin()
            with patch('urllib.request.OpenerDirector.open', return_value=incoming):
                with self.assertRaisesRegex(ModelOutputError, '不完整'):
                    DeepSeekClient(value).complete('JSON', '查看磁盘')
        incoming=HTTPResponse(MemorySocket(len(payload))); incoming.begin()
        with patch('urllib.request.OpenerDirector.open', return_value=incoming):
            self.assertEqual(DeepSeekClient(settings()).complete('JSON', '查看磁盘'), ANALYSIS)

    def test_malformed_ollama_address_is_rejected_and_invalid_edits_keep_status_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ModelUnavailableError, 'OLLAMA_URL'):
                ModelSettings.load(env_file=Path(directory)/'absent.env', environ={'LLM_PROVIDER':'ollama','OLLAMA_URL':'http://[::1/api/chat'})
            with patch.dict(os.environ, {'LLM_PROVIDER':'ollama','OLLAMA_URL':'http://127.0.0.1:11434/api/chat'}):
                app=LocalSafetyApp(Path(directory)/'runtime')
                with patch.dict(os.environ, {'OLLAMA_URL':'http://[::1/api/chat'}):
                    state=app.status()['natural_language']
                    self.assertEqual(state['configuration_state'], 'invalid_update')
                    self.assertEqual(state['endpoint_host'], '127.0.0.1')

    def test_inactive_provider_changes_do_not_claim_active_config_needs_restart(self):
        with patch.dict(os.environ, BASE), tempfile.TemporaryDirectory() as directory:
            app=LocalSafetyApp(Path(directory))
            with patch.dict(os.environ, {'OLLAMA_URL':'http://[::1/api/chat', 'DEEPSEEK_API_KEY':'changed-unused-key'}):
                self.assertEqual(app.status()['natural_language']['configuration_state'], 'active')

    def test_generic_config_uses_own_key_and_does_not_reuse_deepseek_key(self):
        value = settings()
        self.assertEqual(value.provider, 'openai_compatible')
        self.assertEqual(value.model, 'operator-model')
        self.assertEqual(value.api_key, 'compatible-unit-secret')
        self.assertNotIn(value.api_key, repr(value))
        self.assertEqual(settings(LLM_API_KEY='').api_key, '')

    def test_missing_endpoint_or_model_is_explained_without_secret_echo(self):
        for field in ('LLM_BASE_URL', 'LLM_MODEL'):
            with self.subTest(field=field):
                with self.assertRaises(ModelUnavailableError) as raised:
                    settings(**{field:''})
                self.assertIn(field, str(raised.exception))
                self.assertNotIn('compatible-unit-secret', str(raised.exception))

    def test_unsafe_endpoint_is_rejected_before_key_transmission(self):
        for endpoint in ('http://gateway.example/v1', 'https://user:compatible-unit-secret@gateway.example/v1',
                         'https://gateway.example/v1?key=compatible-unit-secret', 'https://gateway.example/v1#secret',
                         'https://gateway.example:99999/v1', 'https://gateway.example/\nprivate',
                         '//gateway.example/v1', 'file:///secret', 'https:///v1'):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ModelUnavailableError) as raised:
                    settings(LLM_BASE_URL=endpoint)
                self.assertNotIn('compatible-unit-secret', str(raised.exception))

    def test_complete_endpoint_and_trailing_slashes_normalize_once(self):
        for endpoint in ('https://gateway.example/custom/v1/', 'https://gateway.example/custom/v1/chat/completions'):
            self.assertEqual(settings(LLM_BASE_URL=endpoint).base_url, BASE['LLM_BASE_URL'])

    def test_request_uses_configured_model_and_only_active_provider_key(self):
        captured = []
        def capture(opener, request, **kwargs):
            captured.append(request)
            return response()
        with patch('urllib.request.OpenerDirector.open', new=capture):
            content = DeepSeekClient(settings()).complete('只输出JSON', '查看磁盘', {'type':'object'})
        self.assertEqual(content, ANALYSIS)
        request = captured[0]
        self.assertEqual(request.full_url, BASE['LLM_BASE_URL']+'/chat/completions')
        self.assertEqual(request.get_header('Authorization'), 'Bearer compatible-unit-secret')
        body = json.loads(request.data)
        self.assertEqual(body['model'], 'operator-model')
        self.assertEqual(body['response_format'], {'type':'json_object'})
        self.assertNotIn('thinking', body)
        self.assertNotIn('temperature', body)
        self.assertNotIn('must-not-use-deepseek-secret', request.data.decode())

    def test_prompt_only_json_and_completion_token_limit_are_explicit(self):
        captured = []
        def capture(opener, request, **kwargs):
            captured.append(json.loads(request.data))
            return response()
        value = settings(LLM_JSON_MODE='prompt_only', LLM_TOKEN_LIMIT_PARAM='max_completion_tokens')
        with patch('urllib.request.OpenerDirector.open', new=capture):
            DeepSeekClient(value).complete('只输出JSON', '查看磁盘')
        self.assertNotIn('response_format', captured[0])
        self.assertNotIn('max_tokens', captured[0])
        self.assertEqual(captured[0]['max_completion_tokens'], 4096)
        for field in ('LLM_JSON_MODE', 'LLM_TOKEN_LIMIT_PARAM'):
            with self.assertRaises(ModelUnavailableError):
                settings(**{field:'invalid'})

    def test_missing_generic_key_never_uses_existing_deepseek_credentials(self):
        with patch('urllib.request.OpenerDirector.open') as send:
            with self.assertRaisesRegex(ModelUnavailableError, 'LLM_API_KEY'):
                DeepSeekClient(settings(LLM_API_KEY='')).complete('JSON', '查看磁盘')
            send.assert_not_called()

    def test_remote_error_is_redacted_and_does_not_claim_deepseek(self):
        def reject(opener, request, **kwargs):
            raise HTTPError(request.full_url, 401, 'compatible-unit-secret', {}, io.BytesIO(b'private remote body compatible-unit-secret'))
        with patch('urllib.request.OpenerDirector.open', new=reject):
            with self.assertRaises(ModelUnavailableError) as raised:
                DeepSeekClient(settings()).complete('JSON', '查看磁盘')
        self.assertIn('LLM_API_KEY', str(raised.exception))
        for private in ('compatible-unit-secret', 'private remote', 'DeepSeek'):
            self.assertNotIn(private, str(raised.exception))

    def test_invalid_or_truncated_generic_response_never_enables_execution(self):
        for payload in (b'not-json', response(finish='length').getvalue(), response(content='').getvalue()):
            with patch('urllib.request.OpenerDirector.open', return_value=io.BytesIO(payload)):
                with self.assertRaises(ModelOutputError):
                    DeepSeekClient(settings()).complete('JSON', '查看磁盘')

    def test_single_step_uses_generic_provider_and_unchanged_validation(self):
        with patch.dict(os.environ, BASE):
            agent = NaturalLanguageInterpreter(output_validator=json.loads)
            with patch('urllib.request.OpenerDirector.open', return_value=response()):
                result = agent.interpret('查看磁盘')
        self.assertTrue(result['actionable'], result)
        self.assertEqual(result['engine'], 'openai_compatible')

    def test_active_snapshot_and_pending_edits_are_separate_and_secret_free(self):
        with patch.dict(os.environ, BASE), tempfile.TemporaryDirectory() as directory:
            app = LocalSafetyApp(Path(directory))
            self.assertIs(app.interpreter.settings, app.tasks.planner.settings)
            first = app.status()['natural_language']
            self.assertEqual(first['configuration_state'], 'active')
            self.assertEqual(first['endpoint_host'], 'gateway.example')
            self.assertTrue(first['api_key_configured'])
            with patch.dict(os.environ, {'LLM_MODEL':'next-model', 'LLM_API_KEY':'new-private-key'}):
                pending = app.status()['natural_language']
                self.assertEqual(pending['configuration_state'], 'restart_required')
                self.assertEqual(pending['model'], 'operator-model')
                self.assertEqual(app.tasks.planner.model, 'operator-model')
                self.assertNotIn('new-private-key', json.dumps(pending))
            with patch.dict(os.environ, {'LLM_BASE_URL':'https://secret@bad.example'}):
                invalid = app.status()['natural_language']
                self.assertEqual(invalid['configuration_state'], 'invalid_update')
                self.assertEqual(invalid['endpoint_host'], 'gateway.example')
            encoded = json.dumps(app.status())
            for private in ('compatible-unit-secret', 'must-not-use-deepseek-secret', '/custom/v1'):
                self.assertNotIn(private, encoded)

    def test_metadata_follows_loaded_ollama_config_not_deepseek_defaults(self):
        with patch.dict(os.environ, {'LLM_PROVIDER':'ollama', 'OLLAMA_MODEL':'local-other-model'}), tempfile.TemporaryDirectory() as directory:
            app = LocalSafetyApp(Path(directory))
            status = app.status()['natural_language']
            self.assertEqual(status['provider'], 'ollama')
            self.assertEqual(status['model'], 'local-other-model')
            self.assertIsNone(status['api_key_configured'])
