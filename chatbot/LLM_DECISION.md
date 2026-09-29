# LLM Approach Decision (Task D)

**Decision:** Use `litellm` as an abstraction layer so the model is swappable via the `MODEL_NAME` environment variable.

| Environment | Model | Why |
|---|---|---|
| Local dev / sensitive scans | `ollama/llama3.2` | Free, private, data never leaves the machine |
| Deployed site (Render) | Cloud model (Gemini or OpenAI) | Render cannot host Ollama; better accuracy on counting/prioritization |

**Config (env vars):**
- `MODEL_NAME` (default `ollama/llama3.2`)
- `OLLAMA_API_BASE` (default `http://localhost:11434`)
- `OPENAI_API_KEY` or `GEMINI_API_KEY` depending on the cloud model

**Interface for Backend (B) and Frontend (C):**
- `analyze(scan_json) -> str` : executive summary (markdown)
- `chat(scan_json, history, question) -> str` : stateless; frontend sends `history` as `[{"role": "user"|"assistant", "content": "..."}]`

**Expected input from A:** a JSON object with a `vulnerabilities` list; each item ideally has `id`, `cve`, `severity`, `title`, `endpoint`, `description`, `remediation`. Extra fields are passed through to the model.

**Known limits:** small local models can miscount and hallucinate; verify with `python vulture_chatbot.py --test` before choosing a model for production.
