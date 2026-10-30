"""Exercise the same real HTTP/Guardrails/approval contracts on a generic API."""
import test_deepseek_tasks as cloud_helpers


class CompatibleTaskTests(cloud_helpers.DeepSeekTaskTests):
    MODEL_ENV = {'LLM_PROVIDER':'openai_compatible', 'LLM_BASE_URL':'https://gateway.example/v1',
                 'LLM_MODEL':'independent-model', 'LLM_API_KEY':'synthetic-task-key',
                 'DEEPSEEK_API_KEY':'must-not-use-deepseek-key'}
    MODEL_URL_PREFIX = 'https://gateway.example/'

    def setUp(self):
        super().setUp()
        self.assertEqual(self.fixture.app.interpreter.provider, 'openai_compatible')
