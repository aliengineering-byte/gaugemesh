# OpenAI-compatible client

With `gaugemesh serve` running:

```sh
curl http://127.0.0.1:8090/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-gaugemesh-tool-mode: lease' \
  -H 'x-gaugemesh-max-tool-rounds: 1' \
  -d '{"model":"local","messages":[{"role":"user","content":"tool:docs-a__search invariants"}],"max_tokens":128}'
```

The GaugeMesh headers explicitly enable one bounded fixture tool round. Omitting
them leaves tool execution off. This verified subset is not complete OpenAI API
compatibility.
