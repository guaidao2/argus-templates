# argus-templates

[中文版](README.zh-CN.md)

Plugins for [argus](https://github.com/guaidao2/argus), kept out of the scanner
itself so they can be published, corrected and versioned on their own cadence.

A plugin is **one YAML document**: argus parses it and executes nothing from it.
That is what makes a collection like this possible at all -- a template is data,
so it can be reviewed and shipped without a build of the scanner. The full
schema is documented in argus's
[plugin guide](https://github.com/guaidao2/argus/blob/main/docs/plugin-guide.md);
each template here documents what it does with it.

## Templates

| Template | Target | Contributes |
| --- | --- | --- |
| [`rpcbind/`](rpcbind/) | ONC RPC portmapper, TCP/UDP 111 | Identifies the port from its RPCB v3 answer (so the disclosed text lands in the report) and renders the registry it gives away: one labelled finding per registered program, plus the UDP reflection/amplification angle |

## Install

```bash
argus --register-plugin ./rpcbind/rpcbind.yaml   # one document
argus --register-plugin ./rpcbind/               # a directory = one pack (see its README)
argus --plugin-dir ./rpcbind/rpcbind.yaml -sV --findings -p 111 10.0.0.9   # one run, no registry
```

Registering a directory walks it recursively and loads every `*.yaml` in it, so
read a template's README before registering the directory: a template may ship a
second, opt-in document next to the default one.

## Verifying a template

Templates that make claims about wire bytes are expected to prove them. Each one
carries a harness that runs a real argus binary against a mock of the target
service and checks the report, including the cases that must **not** fire:

```bash
cd argus && go build -o /tmp/argus ./cmd/argus
cd ../argus-templates
python rpcbind/test/verify.py --argus /tmp/argus
```

## Contributing a template

House rules, drawn from how argus's own rule files are written:

1. **Byte-accurate probes.** Write the wire format out in comments field by
   field, and prove the bytes with a mock rather than by reasoning about them.
   In `send:`, bytes go in YAML double-quoted escapes (`"\x80\x00..."`): YAML
   decodes them to code points and argus turns every rune below `U+0100` back
   into one byte. In `pattern:`, use **single** quotes so the backslash reaches
   RE2, and remember responses are matched as a latin-1 decoding, which is what
   makes `\xNN` mean *byte* NN.
2. **A pattern may only fire on what it claims.** Require the successful-reply
   shape, prefer content that exists only in a successful answer over a status
   code, and anchor a list element to its encoding. If a rule can be satisfied by
   an answer that means something else, it is not finished.
3. **Honest severities.** A finding is a pattern match, not a proof. Say in the
   description what was observed and what it implies, name uncertainty, and keep
   the severity about impact: "this is an exposure, not a flaw" belongs in the
   text when that is the truth.
4. **Nothing that mutates the target.** Probes that change state, trigger denial
   of service or speak to third parties are out of scope, however tempting the
   finding would be. Document the exclusion and how to check it by hand instead.
5. **Bilingual findings.** `title` and `description` are language maps with `en`
   and `zh`; references and tool names are not translated.
6. **A README that says where the information lands** in the report, what the
   template deliberately does not do, and how it was verified.
7. **Tests with negative controls.** A scenario where the rule must stay silent
   is worth more than one more positive case.

RE2 notes that cost time: `\x0[2-4]` is an invalid escape, not a pattern (write
`[\x02-\x04]`); there is no lookahead; a plugin cannot interpolate an extracted
value into finding text, keep disclosures in the finding title instead.

## License

MIT. See [LICENSE](LICENSE).
