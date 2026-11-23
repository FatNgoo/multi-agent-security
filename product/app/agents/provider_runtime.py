"""Shared bounded provider requests, JSON decoding and safe diagnostics."""
import time

from openai import APIConnectionError, APIStatusError, APITimeoutError
from pydantic import ValidationError

from app.config import settings


class ProviderBudgetError(RuntimeError):
    pass


class ProviderOutputError(ValueError):
    pass


def available_calls(tools, role):
    reserve = getattr(tools, 'reserved_llm_calls', 0) if role != 'response' else 0
    return settings.max_llm_calls - reserve - tools.llm_calls


def output_format(mode, schema):
    if mode == 'gemini':
        return {'type': 'json_schema', 'json_schema': {'name': schema.__name__, 'schema': schema.model_json_schema()}}
    return {'type': 'json_object'}


def completion(client, budget, role, mode, **kwargs):
    """Count every attempt, retry only transient failures, and reserve the final advisor's time."""
    tools = budget
    for attempt in range(settings.llm_max_retries + 1):
        tools.checkpoint()
        if available_calls(tools, role) <= 0 or sum(tools.tokens.values()) >= settings.max_llm_tokens:
            raise ProviderBudgetError('Provider call/token budget exhausted')
        reserve = settings.llm_timeout_seconds + 2 if role != 'response' and getattr(tools, 'reserved_llm_calls', 0) else 0
        timeout = min(settings.llm_timeout_seconds, tools.remaining() - reserve - 1)
        if timeout <= 1:
            raise ProviderBudgetError('Not enough time remains for this specialist and the response advisor')
        tools.llm_calls += 1
        options = {'reasoning_effort': settings.gemini_reasoning_effort} if mode == 'gemini' else {}
        try:
            result = client.chat.completions.create(**kwargs, **options, timeout=timeout)
        except (APIConnectionError, APIStatusError) as exc:
            status = getattr(exc, 'status_code', None)
            transient = isinstance(exc, APIConnectionError) or status in {408, 429} or (status is not None and status >= 500)
            # No retry on authentication, missing models or invalid request parameters.
            if not transient or attempt >= settings.llm_max_retries:
                raise
            # Avoid retry storms on rate limiting or an unavailable service.
            delay = min(2 ** attempt, 4)
            if tools.remaining() - reserve <= delay + 2 or available_calls(tools, role) <= 0:
                raise
            # Wait in short pieces so cancellation/deadline checks remain responsive.
            for _ in range(delay * 4):
                tools.checkpoint()
                time.sleep(0.25)
            continue
        if result.usage:
            prompt = result.usage.prompt_tokens or 0
            output = result.usage.completion_tokens or 0
            # Some compatible providers report thinking tokens only in total_tokens.
            output = max(output, (getattr(result.usage, 'total_tokens', None) or prompt + output) - prompt)
            tools.tokens['prompt'] += prompt
            tools.tokens['completion'] += output
        tools.checkpoint()
        if not result.choices:
            raise ProviderOutputError('Provider returned no choices')
        finish = getattr(result.choices[0], 'finish_reason', None)
        if finish == 'length':
            raise ProviderOutputError('Output was truncated by the model token limit')
        if finish in {'content_filter', 'safety'}:
            raise ProviderOutputError('Provider blocked this response')
        return result


def decode_json(content, schema):
    text = (content or '').strip()
    # Some compatible providers wrap otherwise valid JSON in a Markdown fence.
    if text.startswith('```') and text.endswith('```'):
        lines = text.splitlines()
        if lines[0].strip().lower() in {'```', '```json'}:
            text = '\n'.join(lines[1:-1]).strip()
    if not text:
        raise ProviderOutputError('Provider returned empty content')
    return schema.model_validate_json(text)


def diagnostics(exc):
    status = getattr(exc, 'status_code', None)
    if isinstance(exc, APITimeoutError):
        code, message = 'timeout', 'AI chưa trả lời trong thời gian chờ được cấp cho bước này.'
    elif status in {401, 403}:
        code, message = 'authentication', 'API key không hợp lệ hoặc không có quyền dùng model đã cấu hình.'
    elif status == 404:
        code, message = 'model_not_found', 'Không tìm thấy model hoặc endpoint đã cấu hình; kiểm tra tên model và Base URL.'
    elif status == 429:
        code, message = 'rate_limit', 'Provider giới hạn lượt gọi hoặc tài khoản đã hết quota.'
    elif status is not None and status >= 500:
        code, message = 'provider_unavailable', 'Dịch vụ AI đang lỗi hoặc quá tải.'
    elif isinstance(exc, APIConnectionError):
        code, message = 'connection', 'Không kết nối được dịch vụ AI; kiểm tra mạng, DNS hoặc proxy.'
    elif isinstance(exc, ProviderBudgetError):
        code, message = 'budget_exhausted', 'Không còn đủ ngân sách gọi AI hoặc thời gian cho bước này.'
    elif isinstance(exc, ProviderOutputError) and 'truncated' in str(exc):
        code, message = 'output_truncated', 'AI đã dùng hết giới hạn token trước khi trả lời đủ; tăng MAX_OUTPUT_TOKENS hoặc giảm phạm vi.'
    elif isinstance(exc, ProviderOutputError) and 'blocked' in str(exc):
        code, message = 'content_blocked', 'Provider đã chặn phản hồi; không có nhận định AI hợp lệ cho bước này.'
    elif isinstance(exc, (ProviderOutputError, ValidationError, ValueError)):
        code, message = 'invalid_output', 'Phản hồi AI rỗng, bị cắt, sai cấu trúc hoặc có tham chiếu bằng chứng không hợp lệ.'
    elif status == 400:
        code, message = 'invalid_request', 'Model không chấp nhận tham số yêu cầu; kiểm tra cấu hình provider.'
    else:
        code, message = 'provider_error', 'Không hoàn tất được nhận định AI; xem mã lỗi kỹ thuật.'
    result = {'error': type(exc).__name__, 'error_code': code, 'error_message': message}
    if isinstance(exc, ValidationError):
        result['invalid_fields'] = [{'field': '.'.join(map(str, error['loc'])), 'reason': error['type']}
                                    for error in exc.errors(include_input=False)][:8]
    return result
