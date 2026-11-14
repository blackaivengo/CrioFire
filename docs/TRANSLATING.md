# Translating CrioFire

The desktop app (`criofire-ui.exe`) speaks 16 languages: English, Chinese (Simplified), Hindi,
Spanish, Arabic, French, Bengali, Portuguese (Brazil), Russian, Indonesian, Urdu, German,
Japanese, Turkish, Korean and Vietnamese. It follows the Windows display language when it is one
of them, and English otherwise; Settings → Language picks another one (the app restarts).
The command line, the service and the admin console stay in English, so scripts and
administrators always see the same words.

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

## Reviewing a language

The first translations were written with care, but a native speaker should read each language in
the running app before a release, especially the security warnings (blocking modes, panic,
tamper protection, changed programs). Notes for translators can go in the file as keys starting
with `//`; they are ignored.
