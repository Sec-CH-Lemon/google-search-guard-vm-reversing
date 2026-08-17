## Article Link:

https://igorkozlowski.substack.com/p/google-searchguard-anti-bot-system

Tooling for the first article. 
```bash
npm install
node probe-proxy.js
```

## The idea

The challenge is a virtual machine, and reverse engineering it takes weeks. But the original question was only *which browser signals does it collect*, and that does not require reversing anything.

The interpreter installs itself with `.call(this)`, so everything it treats as "the window" is simply what it was handed at startup. Hand it a `Proxy` instead and every property read becomes visible, including reads of properties that **do not exist**, which is exactly where the automation probes live and precisely what an ordinary getter cannot catch.

## The tools

### `probe-proxy.js`: the access table

```bash
node probe-proxy.js
node probe-proxy.js --html=/path/to/challenge.html
```

Prints every property read, `in` check and method call the challenge makes, grouped by surface, with `ABSENT` marking names that do not exist in the run environment.

**Read the `invisible:` marker in the header first.** It runs the challenge twice, tapped and untapped, and compares the tokens byte for byte. `invisible: YES` means the report describes the target. Anything else means it describes the target's reaction to being watched, which is a different and much less useful thing.

That check matters more than it sounds. A stand-in that folds self-references incorrectly still produces a normal-length token with four fifths of the characters matching a clean run, and a completely different remainder. Length tells you nothing. Only byte equality does.

### `verify-claims.js`: re-measure the article

```bash
node verify-claims.js
node verify-claims.js --slow
```

Re-derives the numbers the article states, from your capture, and reports which still hold. `--slow` adds the integrity-check probe, which edits the interpreter source and confirms the challenge notices.

This is the file to run first if you suspect the challenge has changed since publication. Red entries tell you exactly what stopped being true.

## Environment caveat

The probe runs in jsdom, not real Chrome, and jsdom has a poorer environment. So a name showing up as `ABSENT` means one of two quite different things:

- it exists nowhere, in any browser. A genuine automation marker such as ChromeDriver's `$cdc_…` variable, and reading it has exactly one purpose.
- it exists in real Chrome but not in jsdom: `window.chrome`, `trustedTypes`, `navigator.deviceMemory`. For the anti-bot its absence is an inverted signal: this is not Chrome.

The article walks through which of the observed names fall in which group.

## What this does not do

It runs against a saved file and makes no requests to Google.
If you want, you can save and use your own Google HTML page with challenge.
