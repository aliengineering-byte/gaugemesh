# Direct MCP-server-to-model path

An MCP server or another local service can call the model endpoint directly; it
does not need to tunnel model access through deprecated MCP sampling:

```sh
curl http://127.0.0.1:8090/v1/responses \
  -H 'content-type: application/json' \
  -H 'x-gaugemesh-max-output-tokens: 128' \
  -H 'x-gaugemesh-money-budget-micros: 0' \
  -H 'x-gaugemesh-deadline-ms: 3000' \
  -d '{"model":"local","input":"summarize the bounded result","max_output_tokens":128}'
```

The release gate exercises this route through `openai-python==3.6.0`. Configured
providers are selected only after the context, output-token, money, deadline,
policy, and credential-reference boundaries pass.
