# warframe-api-helper

Manually download your Warframe inventory & more.

## What it does

1. Finds the running `Warframe.x64.exe` process.
2. Scans the process's memory for the session authorization string (`?accountId=...&nonce=...`) that the game client already holds.
3. Uses that string to request `inventory.php` from Warframe's API.
4. Writes the result to:
   - `inventory.json` - pretty-printed JSON version.
   - `lastData.dat` - "encrypted" version for AlecaFrame.

## Intended use

This tool is meant for **players who want to grab their own authorization string and inventory data**. Run it while you are logged in to the account whose data you want to export. It only reads the game client's memory, and it does not ask for or obtain your password.

## Notes for developers

If you want to build on this functionality, implement the memory scanning yourself rather than relying on the tool's output files. In particular, cache the authorization string for the lifetime of the game process.

## Disclaimer

This project is not affiliated with or endorsed by Digital Extremes. Using tools that read game client memory may violate the Warframe Terms of Service and could result in action against your account. You use this software at your own risk.

## License

See [LICENSE](LICENSE).
