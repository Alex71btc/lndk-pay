# Testbranch: Zahlungstoast, Liquidität und Activity

Ausgangspunkt: `main`, `ea3150ef53a34242a114f25447e7fc5c8af3120a` (0.3.24).
GitHub-main wurde am 16.11.2026 über die GitHub-Anbindung abgeglichen.
Branch: `codex/payment-toast-liquidity-activity`. Kein Release, Versionsbump oder Deployment.

## Änderungen

- Ein gemeinsames Modul (`app/assets/payment-notifications.js` und `.css`) für
  `/pay` sowie `/app`, einschließlich `/app?setup=1`. Öffentliche Landing- und
  Alias-Seiten laden das Modul nicht; zusätzlich beschränkt es seine Ausführung
  auf die beiden angemeldeten Routen. Der Feed bleibt authentifiziert.
- Kompakter, horizontal mittiger Toast, direkt am Viewport fixiert. Dunkler
  Hintergrund mit 94 % Deckkraft liefert auch ohne Blur Kontrast. Betrag,
  Zahlungsart und der vorhandene privatheitsgefilterte Kommentar bleiben erhalten.
- Zahlungs-Hashes und letzter erfolgreicher Abruf werden im sessionStorage
  gespeichert. Ein Wechsel im selben Tab wiederholt keine bereits gesehenen
  Zahlungen. Die erste Nutzung setzt eine Baseline statt alter Zahlungstoasts.
  Bei 401/403 werden Toasts entfernt und weitere Abrufe gestoppt.
- Klick öffnet `/pay?view=activity&payment=<hash>`. Die Suche läuft über die gesamte
  lokale Activity und findet damit auch Einträge außerhalb der ersten Seite.
- Ein sichtbarer Sprung mit Blitz-SVG oben auf Pay öffnet Activity ohne Reload;
  Formulareingaben bleiben dabei erhalten. Das bestehende sats-Kopieren bleibt
  ein natives Button-Element und kopiert reine Ziffern ohne die Zeile zu öffnen.
- `GET /api/liquidity` liest über die bestehende LND-REST-Verbindung aktive
  Channels. Ausgabe: Channel-ID, lokaler/ausgehender und entfernter/eingehender
  Saldo in sats. Anmeldung und `no-store`; keine Channel-Verwaltung.
- LND-Fehler werden anhand ihrer Ursache übersetzt. NO_ROUTE bleibt „Keine Route
  gefunden“. Lokale Unterdeckung wird nur bei LND INSUFFICIENT_BALANCE oder dann
  ergänzt, wenn die Summe aktiver lokaler Salden unter dem Zahlungsbetrag liegt.
  Nicht verfügbare oder unvollständige Channel-Daten sind keine Nullsalden.
  Unbekannte Ursachen bleiben erhalten. Passende Fehler bieten „Liquidität ansehen“.
- Neue Texte in EN/DE/ES/FR/PL. Der UI-Text-Checker prüft das gemeinsame Modul
  sowohl gegen den Pay- als auch den Konsolen-Katalog.

Die Salden sind keine garantierten send-/empfangbaren Beträge: Reserven,
ausstehende HTLCs, Gebühren und entfernte Routen begrenzen die nutzbare Liquidität.
Die Diagnose verwendet deshalb die Summe der lokalen Salden nur als obere Grenze.
BOLT12-CLI-Fehler werden nur eingeordnet, soweit die CLI eine Ursache liefert;
`src/offers/client_impls.rs::track_payment` reduziert manche LND-Fehler weiterhin
auf `OfferError::PaymentFailure`. Daraus wird keine Liquiditätsursache erfunden.

## Automatisierte Prüfung am 16.11.2026

- **103 ausführbare App-Tests bestanden**, darunter 15 neue Tests: getrennte
  Liquiditätsfälle, aktive Channels, fehlerhafte Daten, Authentifizierung vor
  LND-Zugriff, no-store, gemeinsamer Toast-Lebenszyklus, Activity-Direktlinks und
  Kopier-Click-Handler. Tests führen Produktionsfunktionen in isolierten Python-
  bzw. Node-Fixtures aus; sie ersetzen keinen echten Browser-/LND-Test.
- **11 Root/PWA-Tests bestanden**.
- Katalog-/Platzhalterprüfung und deterministische i18n-Assets bestanden.
- UI-Rohtext-/Schlüsselprüfung, Python-Kompilierung und `git diff --check` bestanden.
- **Vollständige App-Suite noch offen:** 11 vorhandene Testmodule können wegen
  fehlender Laufzeitabhängigkeiten (u.a. FastAPI/httpx) hier nicht importiert werden.
  Der komplette Discovery-Lauf meldet deshalb 114 Fälle, davon 11 Importfehler;
  er ist ausdrücklich nicht vollständig grün. Nach Installation von
  `app/requirements.txt` die vollständige Suite erneut laufen lassen.
- **Visuelle Abnahme offen:** Chromium-Start scheitert in der Sandbox an
  `setsockopt: Operation not permitted`. Es wurde kein Desktop- oder Android-
  Sichttest als bestanden gewertet. Kein echter Zahlungstest ausgeführt.

Reproduzierbare Prüfungen mit installierten Abhängigkeiten:

```bash
python3 scripts/build_i18n.py --check
npm ci --prefix scripts/ui-text-lint
python3 scripts/check_ui_text.py
PYTHONPATH=app python3 -m unittest discover -s app/tests -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Manueller Test durch Alexander

Im bisherigen Checkout zunächst `git status` prüfen und eigene Änderungen sichern:

```bash
git fetch origin
git switch --track origin/codex/payment-toast-liquidity-activity
```

Danach mit dem bisherigen lokalen Build-/Container-Verfahren starten. Produktive
Volumes und lokale Compose-Dateien bleiben unverändert. Browser/PWA neu laden.

- [ ] Desktop: je eine neue Zahlung auf Pay, Setup und App-Konsole; Betrag,
      Zahlungsart und optionalen Kommentar prüfen.
- [ ] Android-PWA: dieselben drei Ansichten prüfen, besonders bei schmalem Display,
      dichtem Text, Scrollen und geöffneter Bildschirmtastatur.
- [ ] Blur im Browser deaktivieren: Hintergrund und Schrift bleiben gut lesbar.
- [ ] Nach einem Toast Pay → Setup → App → Pay wechseln: kein erneuter Toast.
      Während des Wechsels neu eingegangene Zahlung wird einmal angezeigt.
- [ ] Toast anklicken; genau die zugehörige Activity-Zeile öffnet sich. Auch einen
      alten Hash außerhalb der ersten 50 Einträge direkt per URL aufrufen.
- [ ] Direkten Activity-Link ohne Anmeldung öffnen: nach Login bleibt das Ziel
      erhalten. Ungültiger/nicht vorhandener Hash erzeugt keine fremde Auswahl.
- [ ] Öffentliche Landing-/Alias-Seiten ohne Toast und ohne private Feed-Abfrage.
- [ ] Sitzung ablaufen lassen/abmelden: keine neuen Toasts; privater Feed und
      Liquiditäts-Endpoint liefern 401/403. Liquidität zeigt keine alten Salden
      nach fehlgeschlagenem erneuten Abruf.
- [ ] Keine Route trotz ausreichender lokaler Salden: nur „Keine Route gefunden“,
      keine Behauptung lokalen Mangels. Link zur Liquidität vorhanden.
- [ ] LND INSUFFICIENT_BALANCE bzw. belegte Unterdeckung: lokaler Hinweis vorhanden.
- [ ] LND nicht erreichbar: Übersicht „LND-Daten nicht verfügbar“, keine
      Nullsalden oder erfundene Unterdeckung. NO_ROUTE bleibt NO_ROUTE.
- [ ] Touch, Maus, Tab + Enter/Leertaste: sats-Betrag kopiert reine Ziffern,
      ohne die Activity-Zeile umzuschalten. Reale Browser-Aktivierung noch offen;
      automatisiert geprüft sind Button-Markup und gemeinsamer Click-Handler.
- [ ] EN/DE/ES/FR/PL: Toasts, Fehler, Links und Liquidität prüfen.
- [ ] Vollständige App-Suite in der eingerichteten Entwicklungsumgebung ausführen.

## Phoenixd: Ansatzpunkte für einen separaten Prototyp

Kein Phoenixd-Code in diesem Branch. Kandidaten im bestehenden Backend:

| Bereich | Aktuelle Ansatzpunkte | Spätere Trennung |
| --- | --- | --- |
| Senden | `_pay_bolt11_invoice`, `_pay_keysend`, `pay_offer`, `pay_address`, `_pay_address_via_lnurl` | Backend-Adapter für Rechnung/Offer und unterstützte Fähigkeiten; HTTP-Routen, Auth, CSRF und Formulare wiederverwenden. LNDK-CLI und LND-spezifische Fehler separat halten. |
| Empfangen | `_create_bolt11_invoice`, `create_invoice`, `_lookup_invoice`, `_list_invoices`, `_invoice_to_tx_history` | Phoenixd-Rechnungserzeugung und Settlement-Quelle in das vorhandene normalisierte Zahlungsschema überführen. |
| Activity | `_log_tx`, `list_tx_history`, `sync_tx_history`, `_upsert_invoice_history`, `/api/tx-history` | Gemeinsame Activity mit stabilen IDs, Richtung, Status, Betrag, Gebühren, Zeitstempeln und Kommentaren beibehalten. Phoenixd liefert Ereignisse über einen eigenen Adapter. |

Der gemeinsame Toast benötigt nur `/api/tx-history` und bleibt damit vom
Zahlungsbackend unabhängig. Die neue Channel-Übersicht ist ausdrücklich
LND-spezifisch; für Phoenixd Fähigkeiten/Übersicht separat festlegen. API-Version,
Authentifizierung und unterstützte Zahlarten von Phoenixd müssen im eigenen
Auftrag geprüft werden. iPhone-Unterstützung bleibt ebenfalls ein eigener Auftrag.

## UI-Nachbesserung nach manuellem Feedback (16.11.2026)

- Ursache des zusammengezogenen Toasts: Die allgemeine Button-Regel in der
  Konsole setzt `display: inline-flex`. Ein gemeinsamer Toast ohne eigene
  Flex-Richtung erbte deshalb eine horizontale Anordnung. Das gemeinsame CSS
  setzt nun ausdrücklich `display:flex; flex-direction:column` und volle Breite
  für Betrag, Zahlungsart und Kommentar. Die gleiche Regel gilt für alle drei
  Ansichten; CSS-URL auf `v=2` aktualisiert.
- Oben nur noch der Activity-Sprung, jetzt mit vorhandenem Blitz-SVG.
- „Channel Liquidity“ / „Channel-Liquidität“ ist der letzte aufklappbare Abschnitt
  auf Pay. Die kontextabhängige Fehleraktion bleibt erhalten und öffnet ihn direkt.
- Eigenes SVG mit blau-gelber Verteilung und gegenläufigen Pfeilen. Grafische
  Übersicht mit Gesamtsalden, aktiver Channel-Anzahl und einzelnen Channel-Karten.
  Jede Karte zeigt links ausgehend (blau, eigene Seite), rechts eingehend (gelb,
  Gegenseite), die sats-Werte und einen proportionalen Balken mit Prozentangaben.
  Die Breite zeigt die Verteilung innerhalb des jeweiligen Channels, nicht einen
  Vergleich der absoluten Channel-Größen. Nullsalden bleiben als neutraler Balken
  sichtbar; bei fehlenden Daten wird weiterhin keine Null-Liquidität erfunden.
- Vier zusätzliche automatisierte Tests: Verteilung und Grenzfälle (75/25,
  0/0, 100/0, 0/100), Summen, Textsicherheit, CSS-Abgrenzung zur Konsolen-Regel,
  Abschnittsreihenfolge, Symbole, Fehler-Link und alle fünf Sprachkataloge.
- Visuelle Wiederabnahme weiterhin offen: Die lokale HTML-Vorschau durfte vom
  Browserwerkzeug nicht geöffnet werden (file-Protokoll gesperrt). Die Layout-
  Korrektur ist durch Quellcode-/Regressionstests geprüft, nicht als Sichttest
  bestanden markiert.

Erneut manuell prüfen: BOLT12 und Lightning Address mit/ohne Kommentar auf Pay,
Setup und Konsole; drei Textzeilen auch auf Android, langer Kommentar, Scrollen
und Kontrast ohne Blur. Danach Channel-Balken und Direktaufruf aus einem passenden
Zahlungsfehler prüfen. Für das Update auf dem bereits ausgecheckten Testbranch:

```bash
git pull --ff-only origin codex/payment-toast-liquidity-activity
```

Anschließend wie bisher lokal neu bauen/starten und Browser/PWA neu laden.
