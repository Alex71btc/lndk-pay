# Übersetzungsarchitektur

## Ausgangspunkt

Bestandsaufnahme am 2. November 2026 auf Basis von `5ec5fa5` (Version 0.3.19
mit separat geprüftem QR-Fix). Die folgenden Zahlen beschreiben den Zustand vor
der Migration, nicht den Fertigstellungsgrad der neuen Übersetzungen. Der
Android-Companion ist eine native App; die mobile Pay-Oberfläche ist dieselbe
Webseite wie auf dem Desktop.

| Oberfläche | Bisherige Quellen und Besonderheiten |
| --- | --- |
| `/pay` | `frontend/admin/index.html`: Hauptkatalog mit 399 eindeutigen Keys je DE/EN; zusätzlich Scanner-Katalog mit 6 Keys, Tooltip-Mapping und Regex-Patches für Statusmeldungen. Kontakte, Activity, Nostr und NWC befinden sich in derselben Datei. |
| `/app`, Setup und Console | `frontend/public/index.html`: Hauptkatalog mit 123 eindeutigen deutschen und 106 englischen Keys; sieben weitere `T`-Kataloge mit 8, 14, 2, 13, 11, 19 und 39 Keys. Hinzu kommen 20 Alias-Listentexte in einem eigenen DE/EN-Zweig. |
| `/pay-login` | `frontend/admin/pay-login.html`: eigenständiger `LOGIN_TEXT`-Katalog mit 9 Keys je DE/EN; Countdown-Texte als Funktionen. Weitere statische Beschriftungen sind nicht darin enthalten. |
| `/`, `/links` | In `backend/app.py` erzeugtes HTML: eigener Katalog mit 10 Keys je DE/EN, zusätzliche Betragsbeschriftung außerhalb des Katalogs. |
| `/alias/{alias_name}` | In `backend/app.py` erzeugtes HTML: eigener Katalog mit 32 Keys je DE/EN, eigene Sprachauswahl und Renderfunktionen. |
| `/pay-intent` | Vier sichtbare englische Oberflächentexte einschließlich Seitentitel außerhalb eines Übersetzungssystems; sichere Übergabe per Fragment und Session Storage. |
| PWA-Installation | Gemeinsames `frontend/admin/pwa-install.js` verwendet `window.__t`, enthält aber auch eigene englische Fallbacks. Pay und Console übergeben unterschiedliche Key-Namen. |
| Android-Companion | 16 Ressourcen je Sprache in `res/values/strings.xml` (Deutsch als Standard) und `res/values-en/strings.xml`. Java verwendet bereits Ressourcen. Spanisch, Französisch und Polnisch fehlen. |

`frontend/admin.index.broken.backup.html` wird nicht von einer aktiven Seitenroute
ausgeliefert. Die alte Funktion `_pay_login_html()` in `backend/app.py` hat keine
Aufrufstelle; die aktive Login-Route liefert die separate HTML-Datei. Beide
Altbestände gehören ins Inventar, aber nicht in die Abdeckungszahlen aktiver
Seiten. Protokollwerte, Zahlungsziele, Benutzernotizen, Beträge, Relay-Adressen und
Serverdiagnosen sind keine frei zu übersetzenden Oberflächentexte.

## Nachgewiesene Probleme vor der Migration

- Der Pay-Katalog enthält 406 deutsche bzw. 402 englische Einträge für jeweils
  399 Keys. Wiederholungen betreffen `hint.nwc_locked`, `toast.nwc_unlocked` und
  `toast.nwc_locked`; auf Deutsch zusätzlich `hint.nwc_no_qr`,
  `hint.qr_render_failed` und `label.enabled`. JavaScript überschreibt solche
  Einträge unbemerkt.
- Im deutschen Console-Hauptkatalog stehen 144 Einträge für 123 Keys: 19
  unterschiedliche Keys sind mehrfach vorhanden. Englische Texte wurden dort
  teilweise versehentlich in den deutschen Block eingefügt und später nochmals
  deutsch überschrieben. Der separate Toast-Katalog enthält zusätzlich
  `toast.offer_created` doppelt in beiden Sprachen.
- Im englischen Console-Hauptkatalog fehlen 17 der deutschen Keys: vier
  `error.*`, sechs `state.*` und sieben `toast.*`. Andere lokale Kataloge enthalten
  einige Toast-Texte, erweitern aber nicht automatisch `window.__t`. Der verwendete
  Key `toast.nothing_to_copy` fehlt ganz. Eine alleinige Prüfung der beiden
  Hauptkataloge oder eine Suche nach vorhandenen Texten reicht daher nicht aus.
- Beide Hauptübersetzer fallen bei fehlenden Einträgen direkt auf den Key zurück.
  Ein gespeicherter unbekannter Sprachcode kann so die gesamte Seite in Keys
  verwandeln. Sprachermittlung, Speicherung und Rendern werden mehrfach und
  unterschiedlich implementiert.
- Die späten Pay-Scanner-/Tooltip-Patches fragen `window.getLang` ab, das die
  bisherige Pay-Datei selbst nicht bereitstellt. Ihr Ersatzwert ist Englisch.
- `getNwcText()` enthält neun ausschließlich englische Meldungen;
  `getIdentityText()` vier. Weitere Kontaktfehler, Leerzustände, QR-Badges,
  Busy-Texte und Fehlermeldungen stehen direkt in Renderfunktionen.
- Console-Nachbearbeitungen ersetzen `setStatus`, `confirm` und `prompt` und
  erkennen deutsche/englische Sätze mit regulären Ausdrücken. Tooltips werden
  mehrfach zeitversetzt gepatcht. Das ist abhängig von Wortlaut und Ausführungs-
  reihenfolge und lässt sich nicht zuverlässig um drei Sprachen erweitern.
- Datumsdarstellung in Pay ist an zwei Stellen auf DE/EN beschränkt. Die Alias-
  Liste der Console verwendet für jede Sprache außer Englisch deutsche Texte.
- Die Console setzt Übersetzungen pauschal mit `innerHTML`; Pay verwendet
  `textContent`. Einige Katalogwerte enthalten Markup. Platzhalter wie `{status}`
  und `{checked}` werden von Aufrufstellen einzeln ersetzt; es gibt keinen
  gemeinsamen Vertrag für Interpolation.
- Bestehende Tests suchen überwiegend nach Texten im HTML. Beispielsweise
  verlangen Activity-Tests zwei eingebettete Key-Definitionen; solche Prüfungen
  müssen bei der Auslagerung auf Kataloge oder Laufzeitverhalten umgestellt werden.

## Gemeinsamer Vertrag

Die zentrale Browser-Laufzeit liegt unter `app/assets/i18n/runtime.js`. Quellen
sind flache UTF-8-JSON-Dateien unter `app/i18n/{scope}/{en,de,es,fr,pl}.json`.
`scripts/build_i18n.py` erstellt daraus die ausgelieferten
`app/assets/i18n/{scope}.js`. Ein Scope trennt gleichnamige, aber inhaltlich
verschiedene Keys verschiedener Seiten; innerhalb eines Scopes sind Keys stabil
und nach Funktion benannt.

Eine Seite lädt Laufzeit und ihren Katalog vor der Anwendungslogik und wählt den
Scope mit `Bolt12I18n.use(scope)`. Texte kommen über `window.__t(key, {name})` oder
`data-i18n` sowie `data-i18n-placeholder`, `data-i18n-title`,
`data-i18n-aria-label` und `data-i18n-alt`. Neue sichtbare Texte gehören immer in
den zentralen Katalog. Keine neuen lokalen Wörterbücher, Sprach-Ternäre oder
nachträglichen Ersetzungen fertiger Sätze.

Sprachen sind `en`, `de`, `es`, `fr`, `pl`; regionale Browserwerte werden
normalisiert. Englisch ist der verlässliche Fallback für unbekannte Sprachen und
fehlende Einträge. Die bisherige Einstellung `app_lang` bleibt erhalten. Ein
blockiertes Local Storage darf das Rendern nicht abbrechen. Die Sprachauswahl
verwendet `data-i18n-language`; dynamische Ansichten reagieren auf
`i18n:language-changed` und behalten ihre Anwendungszustände bei.

Platzhalter heißen `{name}`, `{seconds}`, `{status}` usw. Kataloge enthalten
Text, kein HTML; Markup gehört in die Seite. Interpolierte Benutzereingaben
müssen an HTML-Rendergrenzen weiterhin escaped werden. Geschäfts-, Wallet-,
Authentifizierungs- und Sicherheitslogik werden nicht für die Übersetzung
umgebaut. Serverdiagnosen bleiben als Details erkennbar; ihre lokalisierten
Oberflächenpräfixe verwenden zentrale Keys.

## Schritte und Abnahme

1. Gemeinsame Laufzeit, deterministischer Katalog-Build und Vertragsprüfungen
   einführen. DE/EN-Bestand übernehmen, Duplikate bewusst auflösen und echte
   englische Fallbacks ergänzen.
2. Login, Übergabeseite und öffentliche Zahlungsseiten migrieren. Bestehende
   Redirect-, Session-, Formular- und Sicherheitsprüfungen unverändert behalten.
3. Console/Setup und Pay jeweils abschnittsweise migrieren: statische Labels,
   dynamische Listen, Dialoge, Statusmeldungen, Scanner, Kontakte, Activity,
   Nostr und NWC. Alte Laufzeiten erst entfernen, wenn ihre Aufrufstellen ersetzt
   und geprüft sind.
4. Für jeden migrierten Scope alle fünf Sprachen vervollständigen. Ein englischer
   Fallback ist eine Absicherung und kein Nachweis einer fertigen Übersetzung.
   Native Android-Ressourcen mit denselben Sprachcodes und englischem Standard
   pflegen; Ressourcen- und Browserimplementierung benötigen jeweils Tests.
5. Desktop und Android mit allen Sprachen prüfen; insbesondere Dialogbreiten,
   lange französische/polnische Texte, Tastatur/Copy-Verhalten, Scanner,
   Sprachwechsel bei geöffneten Listen, Statusmeldungen und Login-Countdown.
   Gerätespezifische Samsung-Tastaturhinweise sind separat am Gerät zu prüfen.

Automatisierte Prüfungen müssen doppelte JSON-Keys vor dem normalen JSON-Parsing
ablehnen, fehlende/zusätzliche Keys je Sprache erkennen und Platzhaltermengen
vergleichen. Sie sollen unbekannte und regionale Sprachen, fehlende Katalog-
einträge, gesperrten Speicher, Interpolation, sprachabhängige Datumsdarstellung
und wiederholte Sprachwechsel testen. HTML/JS-Prüfungen müssen auch dynamische
Key-Familien berücksichtigen. Neue Rohtexte und neue lokale Übersetzungstabellen
werden im CI abgelehnt; temporäre Ausnahmen brauchen einen expliziten, überprüften
Bestand und dürfen nicht automatisch vergrößert werden.

Die bestehenden Python-Anwendungstests, QR-Verhaltenstests und PWA-/Android-
Assettests bleiben Teil der Abnahme. Tests dürfen keine realen Zahlungen oder
Wallet-Mutationen auslösen. Ein Desktop-Test oder DOM-Modell ersetzt keinen
Android-Gerätetest. Ergebnisse und noch offene Geräteprüfungen werden je Commit
benannt; es gibt keinen automatischen Release und keine Versionsanhebung für
diese Entwicklungsarbeit.

## Auslieferung

`/assets` ist bereits öffentlich als `StaticFiles` eingebunden und wird durch
`app/Dockerfile` in das Image kopiert. Zentrale Laufzeit und erzeugte Kataloge
können dort ohne neue Authentifizierungs-Ausnahmen ausgeliefert werden.
`/static` zeigt auf `frontend/public`; `/pay` und `/app` liefern ihre HTML-Dateien
mit No-Store-Headern. Die tatsächlich unter `/service-worker.js` ausgelieferte
Datei ist `frontend/public/service-worker.js` und reicht Requests ausschließlich
ans Netzwerk weiter. Der andere Worker unter `frontend/admin` ist nicht diese
Route. Die Migration führt keine neue Offline- oder Cache-Strategie ein.
