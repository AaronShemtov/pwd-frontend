# pwd-frontend

**Password Generator** — deployed at [pwd.1ms.my](https://pwd.1ms.my/).

Static site for the 1ms.my platform.

## Stack

- Static HTML / CSS / vanilla JS
- nginx-unprivileged (Alpine), ~20 MB
- GitHub Actions → OCIR (linux/arm64)
- Flux Image Automation reconciles the tag bump back to [personal-k8s](https://github.com/AaronShemtov/personal-k8s)

## Shared style

All four 1ms.my sites (1ms.my, cv.1ms.my, infra.1ms.my, pwd.1ms.my) use the same `blueprint.css` file. To keep the visual identity in sync, the file is copied into each repository's `public/` directory.

## Local preview

```bash
cd public
python3 -m http.server 8000
# open http://localhost:8000
```

## License

MIT.
