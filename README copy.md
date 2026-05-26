# pwd-frontend

Password generator — deployed at [pwd.1ms.my](https://pwd.1ms.my).

Client-side cryptographic password generation. The page runs entirely in your browser using `window.crypto.getRandomValues()`. Nothing is sent over the network.

## Features

- Length presets: 8, 12, 16, 20, 24, 32, 48, 64 — with use-case hints
- Custom length: 4 – 128
- Character classes: upper, lower, digits, symbols
- Exclude visually ambiguous characters (`0 O 1 l I |`)
- Exclude DB-unfriendly characters (`' " \ ; $ \` &`)
- Generate 1 / 5 / 10 / 20 passwords at once
- Entropy meter with strength rating (very weak → excellent)
- Copy, regenerate, hide/show toggle
- Dark / light theme with localStorage persistence

## Cryptography

- Randomness source: `window.crypto.getRandomValues()` (browser CSPRNG, backed by OS-level RNG).
- Uniform distribution: rejection sampling against uint32 — no modulo bias.
- Class guarantee: if a class is requested but missing in the output, a random position is replaced with a character from that class.

## Stack

- Static HTML / CSS / vanilla JS — no framework, no build step
- nginx-unprivileged (Alpine) container, ~20 MB
- GitHub Actions → OCIR
- Flux Image Automation closes the GitOps loop in [personal-k8s](https://github.com/AaronShemtov/personal-k8s)

## Local preview

```bash
cd public
python3 -m http.server 8000
# open http://localhost:8000
```

## License

MIT — see `LICENSE`.
