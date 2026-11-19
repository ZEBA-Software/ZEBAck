# Crates für ZEBack Server

Diese beiden Crates gehören zur Anbindung an [ZEBack Server](https://zebasoft.de), das
Speicherziel mit Web-Dashboard. Sie kennen keine Oberfläche und kein Windows und lassen
sich deshalb auch unter Linux bauen und testen.

| Crate | Inhalt |
|---|---|
| `zeback-format` | Das Blockformat: Dateien in Blöcke schneiden (FastCDC), Kennungen (BLAKE3), Kompression (zstd), Verschlüsselung (XChaCha20-Poly1305), Schlüsseldatei (Argon2id), Beschreibung einer Sicherung, Übertragungsformat. ZEBack Server bindet dieses Crate ebenfalls ein – so sprechen beide Seiten garantiert dasselbe Format. |
| `zeback-remote` | Sichern und Wiederherstellen gegen einen ZEBack Server: koppeln, Schlüssel anlegen oder öffnen, nur fehlende Blöcke hochladen, Sicherung abschließen, zurückholen, prüfen. |

```bash
cargo test -p zeback-format -p zeback-remote
```

Die Tests, die beide Crates gegen einen laufenden Server prüfen, liegen im Repository von
ZEBack Server (`crates/zeback-server/tests/client.rs`).

Änderungen am Blockformat brechen bestehende Sicherungen. `zeback-format` enthält dafür
feste Prüfwerte (`chunker::tests::boundaries_are_part_of_the_format`); schlägt dieser Test
fehl, darf die Änderung nur mit einer neuen Formatversion ausgeliefert werden.
