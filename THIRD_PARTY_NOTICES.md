# Third-party notices

Almost everything under `privacyd/` and `hermes_plugin/` is original work released
under the MIT License (see `LICENSE`). The exception is listed under
**Imported code** below.

## Policy

1. If MIT-licensed code is copied or substantially reused, add an entry below
   with the upstream repository, commit SHA, files affected and the full
   upstream copyright + licence text.
2. Do **not** copy source from repositories that carry no licence. In
   particular `saiteja-madha/hermes-privacy-gateway` had no `LICENSE` file and
   no licence field when reviewed (2026-10-06); it is reference-only. Ideas may
   be re-implemented independently.
3. Runtime dependencies are listed in `pyproject.toml` (currently none).

## Candidate MIT upstreams (not yet imported)

| Project | Intended role |
|---|---|
| NousResearch/hermes-agent | middleware wiring, central redaction helpers |
| kvnloo/pii, programasweights/pii | optional semantic PII detector backend |
| microsoft/presidio | optional deterministic analyzer backend |
| explosion/spaCy | optional NLP dependency |

## Imported code

### yubingz/hermes-desensitize (MIT)

- Source: https://github.com/yubingz/hermes-desensitize, commit `4f6697c` (v1.4.1, 2026-09-28)
- Upstream file: `src/hermes_desensitize/plugin.py` (`PATTERNS`, `_DEFAULT_PATH_PATTERNS`, `_ORG_LEAD_STRIP`)
- Used in: `privacyd/detector/chinese_detector.py` (regular expressions adapted; code otherwise rewritten)

```
MIT License

Copyright (c) 2026 yubingz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
