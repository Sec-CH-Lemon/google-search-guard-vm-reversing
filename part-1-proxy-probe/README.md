## Article Link:

https://igorkozlowski.substack.com/p/google-searchguard-anti-bot-system

Tooling for the first article. 
```bash
npm install
node fetch-challenge.js
node probe-proxy.js
```

## The idea

The challenge is a virtual machine, and reverse engineering it takes weeks. But the original question was only *which browser signals does it collect*, and that does not require reversing anything.

The interpreter installs itself with `.call(this)`, so everything it treats as "the window" is simply what it was handed at startup. Hand it a `Proxy` instead and every property read becomes visible, including reads of properties that **do not exist**, which is exactly where the automation probes live and precisely what an ordinary getter cannot catch.

## The tools

### `fetch-challenge.js`: saving a capture

```bash
node fetch-challenge.js
node fetch-challenge.js --query=weather --out=/path/to/challenge.html
```

Requests the search page with no cookies at all and writes the response to `challenge.html`. The cookieless part is the point: a browser Google already trusts gets results instead of the challenge.

What came back is checked before it is kept, using the same call the other tools make, so "saved" means the capture is readable rather than merely present. A run that got results, a consent page or the `/sorry/` page says which of those happened and writes nothing. `--attempts=n` retries with `--delay=ms` between tries, and `--force` saves whatever arrived.

If every attempt returns results rather than the challenge, the answer is a different IP rather than more attempts.

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
