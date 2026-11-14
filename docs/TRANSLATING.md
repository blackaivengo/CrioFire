# Translating CrioFire

The desktop app (`criofire-ui.exe`) and its installer speak 16 languages: English, Chinese (Simplified), Hindi,
Spanish, Arabic, French, Bengali, Portuguese (Brazil), Russian, Indonesian, Urdu, German,
Japanese, Turkish, Korean and Vietnamese. It follows the Windows display language when it is one
of them, and English otherwise; Settings → Language picks another one (the app restarts).
The installer follows the Windows display language the same way. The command line, the service,
the admin console and the CrioFire Server installer stay in English, so scripts and administrators
always see the same words. The license stays in English: it is the binding text.

## How it works

- Every text is written in English where it is used: in the XAML, or in the code as
  `L.T("Clear history")` or `L.T($"Allowed {name} for {minutes} minutes.")`.
- The English text is the key. `src/CrioFire.App/Strings/<code>.json` maps each English text to
  its translation; a text missing from the file (or empty) is shown in English.
- A text with values uses .NET placeholders: `"Allowed {0} for {1} minutes."`. A translation may
  move them (`"{0} für {1} Minuten erlaubt."`) or leave one out, but may not add new numbers.
  `{0:N0}`, `{0:g}` and the like keep their format part. A brace that is not a value is written twice: `{{`.
- XAML texts are translated as each window loads (`UiText`), so the XAML stays plain English.
  Arabic and Urdu mirror the windows (right to left).

## Adding or changing texts

1. Write the English text in the XAML or wrap it in `L.T(...)` in the code.
2. Run `python build/extract-strings.py`: it rewrites `Strings/en.json`, the list of every text.
   CI fails when that list is out of date, or when a translation file keeps texts the app no
   longer has (remove them, or update their keys).
3. Translate the new texts in each `<code>.json` (missing ones show in English until then).

`tests/CrioFire.Tests/LocalizationTests.cs` checks every translation file: valid JSON, only texts
the app has, and placeholders that fit the English text.

## The installer

- `installer/Strings/<culture>.wxl` holds the installer's own texts (the Setup options page, the
  Start menu shortcut, the service description, a few messages) and the font for that language.
  `en-US.wxl` is the list of texts; each language has the same `String` Ids.
- The standard pages (Welcome, License, Install folder, Ready, progress, errors) come translated
  with the WiX UI extension. It has no Indonesian, Vietnamese, Bengali or Urdu, so those four files
  also translate the pages CrioFire shows; texts they do not list (rare error messages) stay English.
- Keep `[ProductName]` and `{\WixUI_Font_Title}` as they are, and at most one `&`: it underlines
  the next letter as the keyboard shortcut. Languages without Latin letters add it at the end, as
  in `学习(&L)`. A text must fit its box on the page; when in doubt, keep it about as long as English.
- `build/package-msi.ps1` builds the installer once per language and stores every language in the
  one MSI. To see a language without changing Windows: `msiexec /i criofire-<version>-x64.msi
  TRANSFORMS=:1081` (the language ID: 1081 Hindi, 1031 German, 1041 Japanese and so on; the list is
  in the script).
- The same test checks every `.wxl` file: all the texts there, the same `[...]` values, one `&`.

## Reviewing a language

The first translations were written with care, but a native speaker should read each language in
the running app and installer before a release, especially the security warnings (blocking modes, panic,
tamper protection, changed programs). Notes for translators can go in the file as keys starting
with `//`; they are ignored.
