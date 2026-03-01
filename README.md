# LLMAssassin

A SpamAssassin plugin that uses any OpenAI-compatible LLM to classify email as spam or ham. Works with OpenAI, Azure OpenAI, Ollama, LM Studio, and any other API speaking the `/v1/chat/completions` protocol.

Integrates natively into SpamAssassin's scoring pipeline — the AI verdict adds to the overall score alongside Bayes, RBLs, and all other SA rules.

---

## What it sends to the AI

Rather than just forwarding the raw email, LLMAssassin builds a structured prompt giving the model full context to make a smart decision:

- **Email headers** — From, To, Subject, Reply-To, X-Mailer, etc.
- **Full Received chain** — every hop the email travelled through
- **Authentication results** — DKIM, SPF, DMARC, ARC pass/fail verdicts
- **SpamAssassin signals** — current SA score, Bayes probability, rules that have already fired (e.g. `URIBL_BLACK`, `BAYES_99`)
- **URLs** — every link extracted from the body (good for catching lookalike/phishing domains)
- **Attachments** — filenames and MIME types flagged as signals
- **Plain text body** — truncated to `llm_max_body_chars` to control token cost

The AI returns: `{"spam": true/false, "confidence": 0.0-1.0, "reason": "<short reason>"}`

---

## Requirements

- SpamAssassin 3.4+
- `curl` in PATH
- An OpenAI-compatible API endpoint
- No CPAN dependencies

---

## Installation

```bash
cp LLMAssassin.pm  /etc/spamassassin/LLMAssassin.pm
cp llmassassin.pre /etc/spamassassin/llmassassin.pre
cp llmassassin.cf  /etc/spamassassin/llmassassin.cf
```

Edit `/etc/spamassassin/llmassassin.cf` — set at minimum:

```
llm_api_base   https://api.openai.com
llm_api_key    sk-your-key-here
llm_model      gpt-4.1
```

Then:

```bash
spamassassin --lint             # verify it loads cleanly
systemctl restart spamassassin
```

---

## Configuration reference

| Option | Default | Description |
|---|---|---|
| `llm_api_base` | `https://api.openai.com` | API server base URL |
| `llm_api_key` | _(empty)_ | Bearer token |
| `llm_model` | `gpt-4.1` | Model name |
| `llm_timeout` | `15` | Request timeout in seconds |
| `llm_spam_score` | `6.0` | Flat score when AI says spam |
| `llm_score_map` | _(empty)_ | Confidence → score map (see below) |
| `llm_fail_closed` | `0` | `0` = fail open, `1` = fail closed |
| `llm_fail_score` | `0.0` | Score on failure when fail_closed=1 |
| `llm_dry_run` | `0` | `1` = log only, never score |
| `llm_skip_authenticated` | `0` | `1` = skip AI for SMTP-auth'd senders |
| `llm_max_calls_per_minute` | `0` | Rate limit (0 = unlimited) |
| `llm_max_body_chars` | `8000` | Max body chars sent to AI |
| `llm_system_prompt` | _(built-in)_ | Override AI system prompt |
| `llm_rate_file` | `/tmp/llmassassin.rate` | Rate limiter state file |

---

## Confidence-based scoring

Instead of a flat score, map confidence ranges to SA scores:

```
llm_score_map   0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0
```

A high-confidence spam verdict scores 8.0, a borderline one scores 2.0. This combines naturally with other SA rules for better accuracy.

---

## SA Whitelist passthrough

LLMAssassin automatically respects SA's existing whitelist config — senders matching `whitelist_from`, `whitelist_auth`, or `def_whitelist_from` in your `local.cf` skip the AI check entirely. No duplicate config needed.

---

## Dry run mode

Test without affecting real mail:

```
llm_dry_run   1
```

The API is called and results are logged via SA's debug system, but no score is ever applied. Watch with:

```bash
tail -f /var/log/mail.log | grep LLMAssassin
```

Flip to `0` when you're happy with the results.

---

## Rate limiting

Cap API calls per minute to control cost on busy servers:

```
llm_max_calls_per_minute   30
```

`0` means unlimited. When the limit is hit, behaviour follows `llm_fail_closed`.

---

## Adding AI verdict to mail headers

In `llmassassin.cf`, uncomment:

```
add_header all LLM-Spam-Reason   _LLMSPAMREASON_
add_header all LLM-Confidence    _LLMSPAMCONFIDENCE_
```

Every processed message will carry headers like:

```
X-Spam-LLM-Spam-Reason: Phishing link detected
X-Spam-LLM-Confidence: 94%
```

---

## Testing

```bash
# Verify plugin loads
spamassassin --lint

# Run a test email through with debug output
spamassassin -D LLMAssassin -t < /path/to/test.eml 2>&1 | grep LLMAssassin

# Quick spam test
cat <<'MAIL' | spamassassin -t
From: winner@lottery-scam.com
To: you@example.com
Subject: You have won $1,000,000!!!

Send us your bank details to claim your prize.
MAIL
```

---

## Examples

### OpenAI
```
llm_api_base   https://api.openai.com
llm_api_key    sk-xxxxxxxxxxxxxxxxxxxxxxxx
llm_model      gpt-4.1
```

### Self-hosted (Ollama, LM Studio, custom proxy)
```
llm_api_base   https://your-server.example.com
llm_api_key    your-token
llm_model      mistral
llm_timeout    30
```

### Local Ollama (no auth)
```
llm_api_base   http://localhost:11434
llm_model      llama3
llm_timeout    60
```

---

## License

Apache License 2.0
