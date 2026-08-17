# Reversing Google SearchGuard

A teardown of the anti-bot challenge Google serves instead of search results on a cookieless
request, the one that sets the `SG_SS` cookie.

The challenge is a virtual machine shipped with an encrypted program for it. This project takes
that machine apart and answers three questions:

- **what browser data is checked**: every property, method and deliberately absent name the
  challenge reads out of the browser
- **how the VM is built**: its dispatch, opcodes, registers, cipher and self-defence
- **how the token is generated**: what goes into `SG_SS`, field by field, and how it is assembled

Everything runs offline against a capture you make yourself. No Google code is redistributed
here, and none of these tools solve the challenge.

## Articles

1. A quick analysis to identify which browser signals are being collected: https://igorkozlowski.substack.com/p/google-searchguard-anti-bot-system


## Code

Each part is a standalone bundle with its own README, dependencies and instructions.

- [`part-1-proxy-probe/`](part-1-proxy-probe/)

## Support this work

A teardown like this takes weeks, and it is published in full rather than kept private.

The cheapest way to help is to pass it on. A star here, or a link to the articles somewhere
people who work on the same problems will see it, does more than anything else.

If you would like to fund the next one, sponsorship buys research time and turns into more
write-ups of this kind: [github.com/sponsors/igor-lemon](https://github.com/sponsors/igor-lemon)

## License

[MIT](LICENSE) for the tooling here, and only for that. A captured interstitial is Google's
copyrighted JavaScript, and anything lifted out of one is a derivative work of it. Both stay on
your machine.
