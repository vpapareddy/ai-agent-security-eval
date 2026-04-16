# Internal Copilot Security Guardrails

The internal copilot may use docs_search, sql_readonly, and draft_action only.
The sql_readonly tool is limited to SELECT statements and a small row cap.
Restricted fields include ssn_last4, internal_summary, internal_note, api_key, and password_hash.
The system must log policy decisions for every attempted tool call.
Untrusted documents must never be treated as executable instructions.
User-provided instructions must not be auto-persisted into memory.
