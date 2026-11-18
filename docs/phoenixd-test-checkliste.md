# Phoenixd: verbleibende Praxistests

Stand: 18.11.2026 · Zwischen-Commit `0aa88cc` · geplante Version 0.3.26.

Erledigte Punkte abhaken. Bei Fehlern Testnummer, gewähltes Backend, Uhrzeit,
Betrag und sichtbare Fehlermeldung festhalten. NWC-Verbindungsstrings und
private Schlüssel nicht in das Testprotokoll kopieren.

## Bereits bestätigt

- [x] Phoenixd-only: BOLT11/LNURL-Zahlungen sowie BOLT12/BIP353-Zahlungen.
- [x] Öffentliche Alias-Seiten, Alias-Erstellung und BIP353-DNS-Reparatur.
- [x] Gleiche Domain für BIP353 und LNURL; BIP353 funktioniert mit Subdomains.
- [x] LNURL-Festbetrag erklärt: Beim 21-sat-Alias sind Minimum und Maximum 21.
- [x] Browser-Toasts auf Pay, Konsole und Einrichtung; keine Wiederholung beim
  Seitenwechsel; nur eine sichtbare Ansicht zeigt dieselbe Zahlung an.
- [x] NWC-Erstellung nach Bootstrap-Fix; Test 1 und 2 laut Nutzerrückmeldung
  vollständig bestanden (NWC und Phoenixd-only-Neustart gemäß Checkliste).
- [x] LNURL-withdraw von LNbits auf StartOS zu Phoenixd; nach Einrichtung eines
  gültigen Let’s-Encrypt-Zertifikats erfolgreich, 100 sats als Eingang sichtbar.
- [x] 304 App-Tests und 11 Root/PWA-Tests sowie Übersetzungs- und UI-Textprüfung.

Automatische Tests ersetzen die folgenden Tests gegen echte Backends und Clients
nicht. Die letzte Vereinfachung des DNS-Dialogs ohne Checkbox ist im genannten
Zwischen-Commit enthalten.

## 1. NWC mit Phoenixd-only — zuerst

Die aktuelle Phoenixd-Testinstanz weiterverwenden. Ein verbundenes LND ist dafür
nicht nötig. Zahlungen an eine andere Wallet richten, nicht an dieselbe Phoenixd-
Wallet zurück. Genügend Guthaben und eine funktionierende Route voraussetzen.

### N1 — Verbindung und Budgetanzeige

Der erste Live-Versuch meldete einen fehlenden Nostr-Serverschlüssel. Dieser
Einstieg ist im Quellcode korrigiert: Die erste NWC-Verbindung erzeugt ihren
internen Schlüssel selbst. Vor der Wiederholung die Test-App neu bauen.
Für diesen Test keinen Notification-nsec eingeben und keine bestehenden
Schlüssel zurücksetzen. Echte alte LND-verschlüsselte Schlüssel benötigen
weiterhin den ursprünglichen LND; ein alter leerer Speicher blockiert nicht mehr.

- [x] Auf `/pay` prüfen, dass **Phoenixd** ausgewählt ist.
- [x] **NWC / Zap Wallet** öffnen und entsperren.
- [x] Neue Verbindung `Phoenixd-Praxistest` anlegen: Einzelzahlung maximal
  **100 sats**, Tagesbudget **50 sats**. `get_info`, `get_balance` und
  `pay_invoice` erlauben.
- [x] Mit deinem bisherigen NWC-Client verbinden. Falls dort noch eine alte
  Verbindung hinterlegt ist, einen getrennten Testeintrag verwenden.
- [x] Verbindung und Guthabenanzeige prüfen.

**Erwartet:** Der Client erreicht BOLT12 Pay über den Relay. Die Guthabenanzeige
zeigt hier das verbleibende **NWC-Budget**, anfangs 50 sats, nicht das gesamte
Phoenixd-Guthaben. Das ist das aktuelle Verhalten von `get_balance`.

### N2 — Einzelzahlungslimit, Bezahlen und Tagesbudget

- [x] In einer anderen Wallet eine Rechnung über **101 sats** erstellen und
  über diese NWC-Verbindung zu bezahlen versuchen.
- [x] Danach zwei unterschiedliche externe Rechnungen über jeweils **21 sats**
  über NWC bezahlen.
- [x] Nach jeder erfolgreichen Zahlung Guthabenanzeige und Lightning-Aktivität
  prüfen. Im Empfänger nachsehen, ob das Geld tatsächlich angekommen ist.
- [x] Eine dritte externe Rechnung über **21 sats** über NWC zu bezahlen versuchen.

**Erwartet:** 101 sats werden wegen des Einzelzahlungslimits abgelehnt.
Die ersten beiden 21-sat-Zahlungen gelingen bei verfügbarer Liquidität und
erscheinen jeweils einmal als **Phoenixd / NWC**. Das Restbudget sinkt auf
29 und danach 8 sats. Die dritte 21-sat-Zahlung wird wegen des Budgets abgelehnt;
beim Empfänger kommt dafür nichts an. Das Budgetlimit ist vom tatsächlichen
Wallet-Guthaben getrennt.

### N3 — Empfang und NWC-Historie

- [x] Falls dein NWC-Client Rechnungen erstellen kann: eine Empfangsrechnung
  anfordern und aus einer anderen Wallet bezahlen.
- [x] Im Client die Zahlung und ihren Status nachladen; dessen Transaktionsliste
  prüfen, falls vorhanden.
- [x] In BOLT12 Pay denselben Eingang mit Backend **Phoenixd** prüfen.

**Erwartet:** Rechnung und Zahlung gehören zu Phoenixd. Der Client erkennt die
bezahlte Rechnung; in der App entstehen keine doppelten Einträge.
Kann der Client Empfang/Transaktionslisten nicht bedienen, diesen Teil als
**mit diesem Client nicht geprüft** notieren, nicht als bestanden.

### N4 — Berechtigungen und Deaktivierung

- [x] Eine zweite NWC-Verbindung mit `get_info`/`get_balance`, aber ohne
  `pay_invoice`, anlegen. Eine Zahlung darüber versuchen.
- [x] Die erste Verbindung in BOLT12 Pay deaktivieren. Erneut eine Anfrage oder
  Zahlung aus dem Client versuchen.
- [x] Wieder aktivieren und die Verbindung erneut prüfen.

**Erwartet:** Die Verbindung ohne Zahlungsrecht zahlt nicht. Die deaktivierte
Verbindung wird nicht mehr bedient; der Client darf dabei auch einen Timeout
anzeigen. Nach Aktivierung funktioniert sie wieder. Zum erneuten Zahlungstest
eine Verbindung mit ausreichendem Restbudget verwenden.

## 2. Neustart mit Phoenixd-only

- [x] Aktive NWC-Verbindung, ausgewählte Wallet, Aliase und vorhandene Historie
  merken; die Test-App normal neu starten, ohne Datenvolume zu löschen.
- [x] Erneut anmelden und dieselben Einträge prüfen.
- [x] Über die bereits gespeicherte NWC-Verbindung Guthaben abfragen und eine
  kleine externe Rechnung bezahlen; gegebenenfalls frische Testverbindung mit
  ausreichendem Budget verwenden.
- [x] Einen bestehenden Alias extern bezahlen und den neuen Eingang prüfen.

**Erwartet:** Phoenixd-Einstellungen, Wallet-Zuordnungen, NWC-Verbindung,
Budgetverbrauch, Aliase und Historie bleiben erhalten. Kein erneutes Pairing
und keine Wiederholung alter Zahlungs-Toasts erforderlich.

## 3. LND + Phoenixd gemeinsam

Erst nach den Phoenixd-only-Tests auf die Dual-Testumgebung wechseln:

```bash
cd ~/lndk-pay
./scripts/start-dual-backend-test.sh
```

Die vorhandene Testinstanz auf Port 8092 und ihr Datenvolume werden weitergenutzt.
Der ursprüngliche LND/LNDK-Container und seine Zugangsdaten müssen noch existieren.
Der Dual-Build enthält inzwischen auch `lndk-cli`. Zum Weiterbauen im Dualbetrieb
diesen Launcher verwenden; der Phoenixd-only-Launcher entfernt den LND-Zugang
wieder aus der Test-App.

### D1 — Beide Richtungen und getrennte Historie

- [x] **LND + LNDK** auswählen. Eine neue BOLT11-Rechnung erstellen.
- [x] Auf **Phoenixd** wechseln, Pay neu laden und diese Rechnung bezahlen.
  Screenshot vom 18.11.2026, 08:38 Uhr: 21 sats, Phoenixd-Ausgang mit 4 sats
  Gebühren und LND-Eingang jeweils abgeschlossen.
- [x] Eine Phoenixd-Rechnung erstellen, dann auf LND wechseln und bezahlen.
  Screenshot vom 18.11.2026, 08:40 Uhr: 21 sats, LND-Ausgang mit 1 sat Gebühr
  und Phoenixd-Eingang jeweils abgeschlossen; Empfangs-Toast sichtbar.

**Erwartet:** Pro Zahlung gibt es zwei echte Vorgänge: Ausgang beim Sender und
Eingang beim Empfänger. Die Historie zeigt beide getrennt und mit dem richtigen
Backend, auch wenn beide denselben Payment Hash haben.

### D2 — Bestehende Aliase und Offers bleiben ihrer Wallet treu

- [x] Phoenixd-Testalias mit LND als ausgewähltem Zahlungsbackend bezahlen:
  direktes BOLT12-Offer und öffentlicher BOLT11-Fallback erfolgreich.
- [x] Beim Phoenixd-Alias **Offer erneuern** ausführen, während LND ausgewählt ist.
  Das erneuerte Offer wieder bezahlen; Eingang bleibt bei Phoenixd.
- [ ] Mit LND ausgewählt einen anderen Testalias erstellen/veröffentlichen.
  Auf Phoenixd wechseln und auch diesen Alias von extern bezahlen.

**Erwartet:** Phoenixd-Aliase empfangen weiterhin auf Phoenixd, LND-Aliase auf LND.
Auch das Erneuern verschiebt keinen Alias zur aktuell ausgewählten Wallet.
BIP353 und LNURL eines Alias verwenden dieselbe gespeicherte Empfangswallet.
Keine vorhandenen produktiven Aliasnamen für diesen Test überschreiben.

**Zwischenstand am 18.11.:** Der öffentliche LNURL-Endpunkt für
`test@phoenixd-test.alex71btc.com` lieferte Cloudflare-Tunnel-Fehler 1033 statt
JSON. Tunnel wieder starten und anschließend LNURL erneut prüfen. Die App
meldet diesen Fehler jetzt gezielt. Die Zahlung über die BIP353-Adresse lief
in einen Timeout, während das direkte Offer funktionierte; Ursache noch offen.
Mit `bash scripts/diagnose-bip353.sh test@phoenixd-test.alex71btc.com` lässt sich
ohne Zahlung vergleichen, ob DNS und gespeicherter Alias dasselbe Offer liefern.

**Nachprüfung:** Die vom Nutzer ausgeführte Diagnose meldet beide Methoden
(`bolt12`, `lnurl`) ohne Fehler und `dns_offer_matches_saved_alias: true`.
Der Systemresolver fällt mit `NoNameservers` aus; der vorhandene HTTPS-Fallback
zu 1.1.1.1 funktioniert. Die LNURL-Grenzen betragen genau 21 sats. Damit sind
Tunnel/Metadaten und der aktuelle DNS-Offer-Vergleich erfolgreich geprüft;
die anschließenden BIP353-Zahlungen sind inzwischen ebenfalls bestätigt (siehe unten).
Die LNURL-Betragsgrenzen allein erklären keinen BIP353-Zahlungs-Timeout.

- [x] Kopieren durch Anklicken funktioniert nach Neustart wieder; der zusätzliche
  Kopierknopf wird auf Nutzerwunsch entfernt.
- [x] Mit LND ausgewählt die Lightning-Adresse über LNURL bezahlt (23 sats),
  außerdem den LNURL-String direkt bezahlt (21 sats).
- [x] BOLT12-Zahlung mit LND über `neu@phoenixd-test.alex71btc.com` (23 sats)
  und `test@phoenixd-test.alex71btc.com` (21 sats) erfolgreich bestätigt;
  zusätzlich funktioniert die ältere externe Adresse `phoenixd@alex71btc.com`.
  Der Timeout ist aktuell verschwunden. Ein ursächlicher Zusammenhang mit
  dem eingegebenen Betrag ist damit nicht bewiesen.
- [x] Nutzer bestätigt die Betragsvorschläge nach Neubau; Vorschau und Vorbelegung: leeres Betragsfeld wird
  mit dem erkannten BOLT12-Mindestbetrag bzw. LNURL-Festbetrag vorgeschlagen.
  Bereits eingegebene Beträge bleiben erhalten. Die Vorschau kennzeichnet
  BOLT12 als Mindestbetrag und LNURL als exakten Betrag. Bei widersprüchlichen
  Beträgen der beiden Wege gibt es keine automatische Vorbelegung.
- [x] LND-Withdraw per Voucher-QR: 100 sats auf LND eingegangen, mit
  Empfangs-Toast und abgeschlossenem Historieneintrag bestätigt.
- [x] LND-Withdraw per **COPY LNURL** nach erneutem Neubau: Nutzer bestätigt
  Erfolg, Screenshot vom 18.11., 11:39 Uhr zeigt die abgeschlossene Anfrage.
  Ein separater abgeschlossener Historieneintrag für diesen Copy-Test ist im
  Screenshot nicht sichtbar; der echte 100-sat-Eingang per QR ist bereits belegt. Der
  Callback-Parameterfehler (`id_unique_hash` ging verloren) ist korrigiert.
  Zusätzlich wird der kopierte Wallet-Link `https://…?lightning=LNURL1…` jetzt
  wie beim QR-Scan entpackt; zuvor rief LND dessen HTML-Startseite ab.
  Phoenixd funktioniert laut Nutzer bereits mit beiden Eingabewegen.
  Erwartet bei **Link prüfen**: `withdrawRequest`, danach beim manuellen
  Empfang ein echter LND-Eingang. Pro Auszahlung einen noch gültigen Voucher
  verwenden; **Link prüfen** selbst erstellt keine Rechnung und zahlt nichts aus.
  HTTPS-Prüfung und sämtliche Provider-Parameter des Callbacks bleiben erhalten.
- [ ] Neue Zahlung empfangen und im Toast Methode plus Empfangsbackend prüfen,
  jeweils mit gleicher und anderer Wallet als aktivem Zahlungsbackend.
- [ ] Dieselbe Backend-Anzeige mit einer neu gebauten Android-Companion-APK prüfen.
  Der Quellcode ist angepasst; die bisher ausgelieferte APK erhält dadurch noch
  keine neue Anzeige. Der vollständige Gradle-Build war in dieser Sitzung durch
  die Netzwerkumgebung blockiert; die geänderte Java-Klasse ließ sich kompilieren.

### D3 — NWC folgt nicht dem Backend-Schalter

- [ ] Auf LND wechseln und über die vorher angelegte Phoenixd-NWC-Verbindung
  eine kleine externe Rechnung bezahlen. Restbudget berücksichtigen.
- [ ] Mit LND ausgewählt eine neue NWC-Verbindung anlegen.
- [ ] Auf Phoenixd wechseln und über diese neue LND-NWC-Verbindung bezahlen.

**Erwartet:** Die erste Verbindung belastet Phoenixd, die zweite LND.
Guthaben/Budgets und Historie im jeweiligen Client passen zur Verbindung.
Der Backend-Schalter routet keine bestehende NWC-Verbindung um.

### D4 — Alte Tabs, Ausfall und Neustart

- [ ] Pay in zwei Tabs öffnen. Im ersten das Backend wechseln. Im zweiten eine
  noch vorbereitete Aktion auslösen.
- [ ] Nur in der Testumgebung eines der Backends vorübergehend unerreichbar
  machen. Eine diesem Backend zugeordnete Aktion versuchen und danach die
  Erreichbarkeit wiederherstellen.
- [ ] Die Dual-Test-App neu starten und Wallet-Auswahl, Aliase, NWC-Verbindungen
  und beide Historien erneut prüfen.

**Erwartet:** Ein veralteter Tab fordert zum Neuladen auf oder aktualisiert sich
vor der Aktion. Keine Zahlung wird unbemerkt aus der anderen Wallet ausgeführt.
Ein nicht erreichbares Backend verursacht einen sichtbaren Fehler; die App
wechselt für gebundene Objekte nicht automatisch zur anderen Wallet.
Nach Neustart bleiben alle Zuordnungen erhalten.

Die öffentliche Standard-Empfangsadresse einer bestehenden Installation bleibt
ebenfalls an ihre ursprüngliche Wallet gebunden. Ein Wechsel des aktiven Backends
ist keine Migration dieser Adresse. Alte LND-verschlüsselte Nostr-Schlüssel
benötigen weiterhin den ursprünglichen LND.

## 4. Nostr, Zaps und Android-Push — soweit genutzt

Diese Erweiterungen sind automatisch getestet, aber für die neue Phoenixd-only-
Integration noch nicht vollständig mit echten Clients bestätigt.

- [ ] **Nostr-Identität:** In der Phoenixd-Testinstallation einen Testalias mit
  einem Testprofil verknüpfen. Falls aktiviert, NIP-05 im Client überprüfen.
- [ ] **Zap-Empfang:** Die LNURL-Lightning-Adresse des Testalias im Nostr-Profil
  verwenden und einen kleinen Zap aus einer anderen Wallet senden.
- [ ] **Zap-Ergebnis:** Eingang in Phoenixd und der App prüfen. Der Nostr-Client
  soll den Zap beziehungsweise Zap-Receipt erkennen.
- [ ] **Nostr-Nachricht:** Falls verschlüsselte Zap-Benachrichtigungen eingerichtet
  sind, Eingang der Nachricht prüfen; nach App-Neustart wiederholen.
- [ ] **Android-Push:** Companion mit der Testinstanz koppeln. App im Hintergrund,
  dann Bildschirm aus. Je einen BOLT11/LNURL- und BOLT12-Eingang auslösen.
- [ ] Genau eine Push-Nachricht je Eingang und korrektes Öffnen der passenden
  Zahlung prüfen. Kommentare mit deaktivierter/aktivierter Kommentaroption testen.

**Erwartet:** Phoenixd-only benötigt hierfür keinen LND-Signer. Nostr-Identität
und Schlüssel bleiben nach Neustart erhalten. Zaps laufen über LNURL, nicht
über BIP353. Für Android-Push muss ein UnifiedPush-Distributor eingerichtet sein;
die bereits geprüften Browser-Toasts ersetzen diesen Test nicht.

## 5. LNURL-Login und Withdraw

- [ ] **LNURL-auth mit Phoenixd:** Bei einem Testdienst anmelden; dieselbe Wallet
  nach App-Neustart erneut verwenden. Erwartet: dieselbe dienstbezogene Identität.
- [ ] **LNURL-auth mit LND:** Im Dualbetrieb wiederholen. Erwartet: erfolgreiche
  Anmeldung, aber eine eigene Identität; LND und Phoenixd teilen kein Login-Konto.
- [x] **LNURL-withdraw mit Phoenixd:** Gültiger Voucher von LNbits auf StartOS
  nach Let’s-Encrypt-Einrichtung eingelöst; Eingang von 100 sats bestätigt.
- [x] **LNURL-withdraw mit LND per QR:** Eingang von 100 sats bestätigt.
- [x] **LNURL-withdraw mit LND per COPY LNURL:** Anfrage nach Wrapper-Fix
  erfolgreich; Nutzer bestätigt dies am 18.11., 11:39 Uhr.

Keine Vouchers aus derselben empfangenden Wallet für diesen Test verwenden.
Die früheren HTTP-/TLS-Fehler sind von den inzwischen erfolgreichen QR- und
Copy-Tests zu unterscheiden. LNURL-auth bleibt auf beiden Backends offen.

## 6. Update und fertige Pakete — abschließend gemeinsam

- [ ] Die tatsächlich gebauten Produktionsimages auf amd64 und arm64 starten.
- [ ] Eine bestehende Umbrel-/StartOS-Installation mit vorhandenen Aliasen,
  Historie, Nostr-Konfiguration und NWC-Verbindung aktualisieren.
- [ ] Prüfen: Anmeldung funktioniert; alte LND-Objekte bleiben bei LND; neue
  Phoenixd-Funktionen sind nutzbar; vorhandene Clients müssen nicht neu gekoppelt
  werden; DNS-Reparatur erscheint nur für tatsächlich betroffene Aliase.
- [ ] Bei Migration einer alten Historie das automatisch erstellte Backup unter
  `/data/backups/before-wallet-history-v1` prüfen. Nach weiterem Neustart bleibt
  dieser ursprüngliche Snapshot unverändert.
- [ ] Wiederherstellung des Snapshots ausschließlich in einer getrennten
  Testinstallation prüfen, nicht über dem aktuellen produktiven Datenbestand.
- [ ] App nach Plattformneustart erneut prüfen. LND-Pfad auf den vorgesehenen
  unterstützten LND-Versionen testen, insbesondere BOLT11 und BOLT12/LNDK.
- [ ] Festlegen und prüfen, ob die jeweiligen Store-Pakete eine Installation
  ohne LND erlauben. Das folgt nicht automatisch aus dem funktionierenden
  Phoenixd-only-Docker-Test.

Imagebau, Paketdateien, genaue Versionen/Digests, Merge und Veröffentlichung
bearbeiten wir gemeinsam nach den Funktionstests. Noch kein Release erfolgt.

## Nicht als fehlgeschlagenen Test zählen

- Phoenixd hat kein Keysend über seine HTTP-API. Das Channel-Tool bleibt LND-
  spezifisch. Bestimmte erweiterte Offer-Optionen sind ebenfalls backendabhängig.
- Ein Routing-/Liquiditätsfehler allein belegt keinen Alias- oder NWC-Fehler.
  Die beiden Endpunkte und den tatsächlichen Zahlungsausgang prüfen.
- Bei unklarem Zahlungsausgang nicht mehrfach blind absenden. Erst im Backend
  und beim Empfänger prüfen; unbekannte Vorgänge dürfen nicht automatisch
  erneut bezahlt werden.

## Kurzes Ergebnisprotokoll

| Test | Datum | Backend/Client | Ergebnis / Beobachtung |
|---|---|---|---|
| N1–N4 | 18.11.2026 | Phoenixd / Amethyst | Test 1 laut Nutzer vollständig bestanden; normale Historie korrekt |
| Neustart Phoenixd-only | 18.11.2026 | Phoenixd | Test 2 laut Nutzer vollständig bestanden |
| D1–D4 | | | |
| Nostr/Zaps/Android-Push | | | |
| LNURL-auth/withdraw | 18.11.2026 | Phoenixd / LND / LNbits StartOS | Withdraw je 100 sats bei Phoenixd und LND (QR) bestätigt; LND COPY LNURL Anfrage nach Wrapper-Fix erfolgreich; Auth offen |
| Plattform-Update/Pakete | | | |

## Folgeausbau: Amethyst-Zap-Filter

Die normale NWC-Transaktionshistorie funktioniert laut Nutzer mit LND und
Phoenixd. Amethysts getrennte Listen für Zaps und Nicht-Zaps wurden dagegen
als leer gemeldet. Das ist noch keine abgeschlossene Ursachenanalyse.

Im am 18.11.2026 eingesehenen Amethyst-Quellcode prüft der Zap-Filter
`tx.parsedMetadata()?.nostr != null`; der Nicht-Zap-Filter prüft das Gegenteil.
BOLT12 Pay liefert in `list_transactions` derzeit kein `metadata`-Objekt.
Das erklärt fehlende Zap-Zuordnungen, allein jedoch keine leere Nicht-Zap-Liste.
Installierte Client-Version und konkrete Antworten müssen separat geprüft werden.

- [ ] Installierte Amethyst-Version und Verhalten beider Filter reproduzieren.
- [ ] Vollständige NWC-Transaktionsdaten samt vorhandenen, überprüften
  Zap-Requests/-Receipts, Gegenstelle und Kommentar planen. Keine gewöhnliche
  Zahlung allein aufgrund eines Beschreibungsfeldes als Zap markieren.
- [ ] Auch ausgehende Zaps untersuchen: Nicht jede NWC-Zahlungsanfrage enthält
  schon die Identität oder den bezahlten Beitrag. Fehlende Zuordnungen nicht erfinden.
- [ ] Metadaten für LND und Phoenixd konsistent und ausschließlich im jeweiligen
  Wallet-Kontext bereitstellen; `lookup_invoice` und `list_transactions` abstimmen.
- [ ] Gemischte Historie testen: echter Zap, gewöhnliche Rechnung, BOLT12-Zahlung,
  unbekannte Metadaten, Filterwechsel und mehrere Seiten.

Dies ist ein nachgelagerter Kompatibilitätsausbau; die neue Funktion wurde noch
nicht implementiert oder als Teil des aktuellen Releases zugesagt.

Quellen (Stand des Abrufs 18.11.2026):

- [Amethyst WalletViewModel](https://github.com/vitorpamplona/amethyst/blob/main/commonsUI/src/commonMain/kotlin/com/vitorpamplona/amethyst/commons/ui/screen/loggedIn/wallet/WalletViewModel.kt)
- [NWC-05: Transaktionshistorie und Metadaten](https://github.com/nostr-wallet-connect/nwc/blob/main/05.md)
