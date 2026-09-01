#!/usr/bin/env python3
"""Exercise GaugeMesh through the exact-pinned official OpenAI Python SDK."""

from __future__ import annotations

import argparse

import openai
from openai import OpenAI


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18141/v1")
    args = parser.parse_args()

    client = OpenAI(
        api_key="loopback-no-key",
        base_url=args.base_url,
        max_retries=0,
        timeout=5.0,
    )
    models = client.models.list()
    if "local" not in {model.id for model in models.data}:
        raise SystemExit("local model missing from SDK model list")

    chat = client.chat.completions.create(
        model="local",
        messages=[{"role": "user", "content": "hello from the SDK"}],
        max_tokens=32,
    )
    if chat.choices[0].message.content != "fixture: hello from the SDK":
        raise SystemExit("unexpected chat completion")

    response = client.responses.create(
        model="local",
        input="hello from responses",
        max_output_tokens=32,
    )
    if response.output_text != "fixture: hello from responses":
        raise SystemExit("unexpected Responses API result")

    print(f"PASS openai-python={openai.__version__} base_url={args.base_url}")


if __name__ == "__main__":
    main()
