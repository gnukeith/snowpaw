# macOS app bundle

```bash
packaging/macos/build-app.sh
```

This builds the desktop client and its sandboxed render worker (`snowpaw-render`, which
highlights code, typesets math and decodes pictures) and wraps both in
`target/release/snowpaw.app`. Without the worker next to the client, messages show as
plain text and pictures as initials. Launch the
app from there (or copy it to `/Applications`) to get the snowpaw icon in the Dock,
Finder and the app switcher. Running `target/release/snowpaw` directly from a terminal
still works, but macOS shows a generic icon for bare executables.

`--no-build` packages the existing `target/release/snowpaw` without rebuilding it.

## The icon

| File | What it is |
| --- | --- |
| `snowpaw.icon/` | Icon Composer source for macOS 26 and later. One full-bleed layer per appearance: Fresh Snow in light mode, Night Snow in dark mode. The system adds the shape, margin, shadow and edge light, so the art has none of its own. Glass is off, to keep the pressed-into-snow look. |
| `snowpaw.icns` | Fallback: Fresh Snow on the classic macOS grid. Used by macOS 15 and earlier, and on macOS 26+ when no `Assets.car` is available (light only). |
| `Assets.car` (optional) | `snowpaw.icon` compiled by Xcode 27. If present, the script uses it on machines without Xcode 27. |

The light/dark icon has to be compiled by `actool` from **Xcode 27 or later**; older
versions drop the dark appearance without an error. The script does this automatically
when it finds Xcode 27 (set `DEVELOPER_DIR` to point at a specific Xcode). Without it,
the app gets the light icon only.

To check a compiled catalog, `assetutil --info Assets.car` should list icon stacks for
both `NSAppearanceNameAqua` and `NSAppearanceNameDarkAqua`.

The editable sources are in `design/icon/`: `snowpaw/icon-composer/*.svg` for the two
layers (exported to PNG at 1024 × 1024, fully opaque), and `snowpaw/macos/` for the
fallback `.icns`.
