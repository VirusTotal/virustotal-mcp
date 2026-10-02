# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Host file metadata stays bounded and never enables a downloader in local stdio."""

import json
from contextlib import asynccontextmanager

import httpx
import pytest
from analysis_helpers import SHA, TOKEN, submission_response
from mcp import Client

from vt_mcp.analyses import AnalysisError
from vt_mcp.reports import VTAIError
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio
FILE = {
    "download_url": "https://files.example.invalid/fixture?sig=private",
    "file_id": "file_fixture",
}


@asynccontextmanager
async def lifespan(_):
    yield None


def never(_):
    pytest.fail("Discovery or invalid arguments must not bind a reader")


def server(binding=never):
    return create_report_server(
        lifespan=lifespan,
        bind_reports=never,
        bind_analyses=never,
        bind_submissions=never,
        bind_network_submissions=never,
        bind_chatgpt_submissions=binding,
    )


async def test_file_descriptor_has_exact_openai_shape_and_write_annotations():
    async with Client(server()) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "submit_chatgpt_file")
        assert len(client.instructions) < 2048
    schema = tool.input_schema
    shape = schema["$defs"][schema["properties"]["file"]["$ref"].split("/")[-1]]
    assert schema["required"] == ["file"] and set(schema["properties"]) == {"file"}
    assert shape["required"] == ["download_url", "file_id"]
    assert shape["additionalProperties"] is False
    assert set(shape["properties"]) == {"download_url", "file_id", "mime_type", "file_name"}
    assert all(
        field["type"] == "string" and "anyOf" not in field for field in shape["properties"].values()
    )
    wire = tool.model_dump(by_alias=True, exclude_none=True)
    assert wire["_meta"] == {"openai/fileParams": ["file"]}
    assert wire["annotations"] == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }


async def test_no_chatgpt_tool_in_read_only_hosts_or_local_stdio():
    for instance in [
        create_report_server(lifespan=lifespan, bind_reports=never),
        create_server(
            Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("HTTP"))
        ),
    ]:
        async with Client(instance) as client:
            assert "submit_chatgpt_file" not in {
                tool.name for tool in (await client.list_tools()).tools
            }


@pytest.mark.parametrize("bindings", [{}, {"bind_submissions": never}, {"bind_analyses": never}])
def test_host_must_supply_receipt_and_analysis_recovery(bindings):
    with pytest.raises(ValueError, match="file receipts and analysis reads"):
        create_report_server(
            lifespan=lifespan, bind_reports=never, bind_chatgpt_submissions=never, **bindings
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"file": None},
        {"file": FILE, "other": FILE["download_url"]},
        {"file": {"download_url": FILE["download_url"]}},
        {"file": {**FILE, "mime_type": None}},
        {"file": {**FILE, "file_name": 1}},
        {"file": {**FILE, "file_id": ""}},
        {"file": {**FILE, "file_id": "x" * 257}},
        {"file": {**FILE, "download_url": "x" * 8193}},
        {"file": {**FILE, "file_name": "x" * 256}},
        {"file": {**FILE, "mime_type": "x" * 256}},
        {"file": {**FILE, "file_name": "line\nsecret"}},
        {"file": {**FILE, "file_name": "id_rsa"}},
        {"file": {**FILE, "file_name": ".env"}},
        {"file": {**FILE, "file_name": "C:\\Users\\you\\credentials.json"}},
        {"file": {**FILE, "file_name": "C:credentials.json"}},
        {"file": {**FILE, "file_name": "c:.env"}},
        {"file": {**FILE, "file_name": "/home/you/.npmrc"}},
        {"file": {**FILE, "file_id": "file\x00secret"}},
        {"file": {**FILE, "extra": FILE["download_url"]}},
    ],
)
async def test_invalid_input_is_closed_before_binding_or_sdk_error_echo(arguments):
    async with Client(server()) as client:
        result = await client.call_tool("submit_chatgpt_file", arguments)
    assert result.is_error
    assert result.structured_content["error"]["code"] == "invalid_input"
    assert FILE["download_url"] not in result.content[0].text
    assert "input_value" not in result.content[0].text


async def test_optional_fields_are_preserved_and_binding_is_per_call_with_actual_sha():
    seen = []
    bound = []

    class Reader:
        async def submit_chatgpt_file(self, file):
            seen.append(file)
            return submission_response()

    def bind(ctx):
        bound.append(ctx)
        return Reader()

    async with Client(server(bind)) as client:
        for file in [
            FILE,
            {**FILE, "file_name": "public.bin", "mime_type": "application/octet-stream"},
            {**FILE, "file_name": "", "mime_type": ""},
        ]:
            result = await client.call_tool("submit_chatgpt_file", {"file": file})
            assert not result.is_error and result.structured_content == submission_response()
            assert FILE["download_url"] not in result.content[0].text
    assert seen == [
        FILE,
        {**FILE, "file_name": "public.bin", "mime_type": "application/octet-stream"},
        {**FILE, "file_name": "", "mime_type": ""},
    ]
    assert len(bound) == 3


@pytest.mark.parametrize("mode", ["unknown", "exception", "echo", "fixed_download_error"])
async def test_failure_recovery_and_signed_url_sanitization(mode):
    class Reader:
        async def submit_chatgpt_file(self, _):
            if mode == "unknown":
                raise AnalysisError(
                    "submission_unknown",
                    submission=submission_response(status="submission_unknown"),
                )
            if mode == "exception":
                raise RuntimeError(FILE["download_url"])
            if mode == "echo":
                raise VTAIError("download_failed", FILE["download_url"])
            raise VTAIError("download_unavailable", "Request a fresh attachment link.")

    async with Client(server(lambda _: Reader())) as client:
        result = await client.call_tool("submit_chatgpt_file", {"file": FILE})
    assert result.is_error
    assert FILE["download_url"] not in json.dumps(result.model_dump())
    if mode == "unknown":
        assert result.structured_content["submission"]["sha256"] == SHA
        assert result.structured_content["error"]["retryable"] is False
    elif mode == "echo":
        assert result.structured_content["error"]["code"] == "invalid_response"
    elif mode == "fixed_download_error":
        assert result.structured_content["error"]["message"] == "Request a fresh attachment link."


async def test_missing_report_suggests_only_enabled_attachment_capability():
    class Reports:
        async def get_file_report(self, _):
            raise VTAIError("not_found", "Unknown file", http_status=404)

    instance = create_report_server(
        lifespan=lifespan,
        bind_reports=lambda _: Reports(),
        bind_analyses=never,
        bind_submissions=never,
        bind_chatgpt_submissions=never,
    )
    async with Client(instance) as client:
        result = await client.call_tool("get_file_report", {"hash": SHA})
    assert result.is_error
    steps = " ".join(result.structured_content["error"]["next_steps"])
    assert "submit_chatgpt_file" in steps and "host-provided" in steps
    assert "or fetch file bytes from a URL" not in steps
    assert "submit_local_file" not in steps


@pytest.mark.parametrize("raw", [None, {}, {"sha256": "not-a-sha256"}])
async def test_invalid_download_result_is_not_a_submission_receipt(raw):
    class Reader:
        async def submit_chatgpt_file(self, _):
            return raw

    async with Client(server(lambda _: Reader())) as client:
        result = await client.call_tool("submit_chatgpt_file", {"file": FILE})
    assert result.is_error and result.structured_content["error"]["code"] == "invalid_response"
    assert "submission" not in result.structured_content
